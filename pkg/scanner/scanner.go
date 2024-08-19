package scanner

import (
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/GlobalCyberAlliance/domain-security-scanner/v3/pkg/cache"
	"github.com/GlobalCyberAlliance/domain-security-scanner/v3/pkg/dns"
	"github.com/panjf2000/ants/v2"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/spf13/cast"
)

const (
	ErrInvalidDomain = "invalid domain name"
)

type (
	Scanner struct {
		// cache is a simple in-memory cache to reduce external requests from the scanner.
		cache *cache.Cache[Result]

		// cacheDuration is the time-to-live for cache entries.
		cacheDuration time.Duration

		// DNS client shared by all goroutines the scanner spawns.
		dnsClient *dns.Client

		// dnsBuffer is used to configure the size of the buffer allocated for DNS responses.
		dnsBuffer uint16

		// logger is the logger for the scanner.
		logger zerolog.Logger

		// pool is the pool of workers for the scanner.
		pool *ants.Pool

		// poolSize is the size of the pool of workers for the scanner.
		poolSize uint16

		advisor *Advisor

		// scanDNSSEC is a flag to enable DNSSEC scanning.
		scanDNSSEC bool
	}

	// Option defines a functional configuration type for a *Scanner.
	Option func(*Scanner) error

	// Result holds the results of scanning a domain's DNS records.
	Result struct {
		Domain    string   `json:"domain" yaml:"domain,omitempty" doc:"The domain name being scanned." example:"example.com"`
		Error     string   `json:"error,omitempty" yaml:"error,omitempty" doc:"An error message if the scan failed." example:"invalid domain name"`
		BIMI      string   `json:"bimi,omitempty" yaml:"bimi,omitempty" doc:"The BIMI record for the domain." example:"https://example.com/bimi.svg"`
		DKIM      string   `json:"dkim,omitempty" yaml:"dkim,omitempty" doc:"The DKIM record for the domain." example:"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"`
		DMARC     string   `json:"dmarc,omitempty" yaml:"dmarc,omitempty" doc:"The DMARC record for the domain." example:"v=DMARC1; p=none"`
		MX        []string `json:"mx,omitempty" yaml:"mx,omitempty" doc:"The MX records for the domain." example:"aspmx.l.google.com"`
		NS        []string `json:"ns,omitempty" yaml:"ns,omitempty" doc:"The NS records for the domain." example:"ns1.example.com"`
		SPF       string   `json:"spf,omitempty" yaml:"spf,omitempty" doc:"The SPF record for the domain." example:"v=spf1 include:_spf.google.com ~all"`
		STS       string   `json:"mta-sts,omitempty" yaml:"mta-sts,omitempty" doc:"The MTA-STS record for the domain." example:"v=STSv1; id=20210803T010200;"`
		STSPolicy string   `json:"mta-sts-policy,omitempty" yaml:"mta-sts-policy,omitempty" doc:"The MTA-STS policy for the domain." example:"version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.example.net\nmax_age: 86400\n"`
		DNSSEC    string   `json:"dnssec,omitempty" yaml:"dnssec,omitempty" doc:"The DNSSEC record for the domain." example:"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"`
	}
)

func New(logger zerolog.Logger, timeout time.Duration, opts ...Option) (*Scanner, error) {
	if timeout <= 0 {
		return nil, errors.New("timeout must be greater than 0")
	}

	dnsClient, err := dns.New(timeout, 4096, 0, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS client: %w", err)
	}

	scanner := &Scanner{
		dnsClient: dnsClient,
		dnsBuffer: 4096,
		logger:    logger,
		poolSize:  uint16(runtime.NumCPU()),
	}
	scanner.advisor = NewAdvisor(timeout, scanner.cacheDuration)
	for _, opt := range opts {
		if err := opt(scanner); err != nil {
			return nil, errors.Wrap(err, "apply option")
		}
	}

	// Initialize cache
	scanner.cache = cache.New[Result](scanner.cacheDuration)

	// Create a new pool of workers for the scanner
	pool, err := ants.NewPool(int(scanner.poolSize), ants.WithExpiryDuration(timeout), ants.WithPanicHandler(func(err interface{}) {
		scanner.logger.Error().Err(errors.New(cast.ToString(err))).Msg("unrecoverable panic occurred while analysing pcap")
	}))
	if err != nil {
		return nil, fmt.Errorf("failed to create scanner pool: %w", err)
	}

	scanner.pool = pool

	return scanner, nil
}

// Scan scans a list of domains and returns the results.
func (s *Scanner) Scan(domains ...string) ([]*Result, error) {
	if s.pool == nil {
		return nil, errors.New("scanner is closed")
	}

	for _, domain := range domains {
		if domain == "" {
			return nil, errors.New("empty domain")
		}
	}

	if len(domains) == 0 {
		return nil, errors.New("no domains to scan")
	}

	var mutex sync.Mutex
	var results []*Result
	var wg sync.WaitGroup

	for _, domainToScan := range domains {
		wg.Add(1)

		if err := s.pool.Submit(func() {
			defer func() {
				wg.Done()
			}()

			var err error
			result := &Result{
				Domain: domainToScan,
			}

			if s.cache != nil {
				scanResult := s.cache.Get(domainToScan)
				if scanResult != nil {
					s.logger.Debug().Msg("cache hit for " + domainToScan)
					mutex.Lock()
					results = append(results, scanResult)
					mutex.Unlock()
					return
				}

				s.logger.Debug().Msg("cache miss for " + domainToScan)

				defer func() {
					s.cache.Set(domainToScan, result)
				}()
			}

			// check that the domain name is valid
			result.NS, err = s.dnsClient.GetTypeNS(domainToScan)
			if err != nil || len(result.NS) == 0 {
				// check if TXT records exist, as the nameserver check won't work for subdomains
				records, err := s.dnsClient.GetDNSAnswers(domainToScan, dns.TypeTXT)
				if err != nil || len(records) == 0 {
					// fill variable to satisfy deferred cache fill
					result = &Result{
						Domain: domainToScan,
						Error:  ErrInvalidDomain,
					}

					mutex.Lock()
					results = append(results, result)
					mutex.Unlock()

					return
				}
			}

			var errs []string
			scanWg := sync.WaitGroup{}
			scanWg.Add(7)

			// Get BIMI record
			go func() {
				defer scanWg.Done()
				result.BIMI, err = s.dnsClient.GetTypeBIMI(domainToScan)
				if err != nil {
					errs = append(errs, "bimi:"+err.Error())
				}
			}()

			// Get DKIM record
			go func() {
				defer scanWg.Done()
				result.DKIM, err = s.dnsClient.GetTypeDKIM(domainToScan)
				if err != nil {
					errs = append(errs, "dkim:"+err.Error())
				}
			}()

			// Get DMARC record
			go func() {
				defer scanWg.Done()
				result.DMARC, err = s.dnsClient.GetTypeDMARC(domainToScan)
				if err != nil {
					errs = append(errs, "dmarc:"+err.Error())
				}
			}()

			// Get MX records
			go func() {
				defer scanWg.Done()
				result.MX, err = s.dnsClient.GetTypeMX(domainToScan)
				if err != nil {
					errs = append(errs, "mx:"+err.Error())
				}
			}()

			// Get SPF record
			go func() {
				defer scanWg.Done()
				result.SPF, err = s.dnsClient.GetTypeSPF(domainToScan)
				if err != nil {
					errs = append(errs, "spf:"+err.Error())
				}
			}()

			// Get MTA-STS record
			go func() {
				defer scanWg.Done()
				result.STS, result.STSPolicy, err = s.dnsClient.GetTypeSTS(domainToScan)
				if err != nil {
					errs = append(errs, "mta-sts:"+err.Error())
				}
			}()

			go func() {
				defer scanWg.Done()
				if s.scanDNSSEC {
					result.DNSSEC, err = s.dnsClient.GetTypeDNSSEC(domainToScan)
					if err != nil {
						errs = append(errs, "dnssec:"+err.Error())
					}
				}
			}()

			scanWg.Wait()

			if len(errs) > 0 {
				result.Error = strings.Join(errs, "; ")
			}

			mutex.Lock()
			results = append(results, result)
			mutex.Unlock()
		}); err != nil {
			return nil, err
		}
	}

	wg.Wait()

	return results, nil
}

func (s *Scanner) ScanZone(zone io.Reader) ([]*Result, error) {
	if s.pool == nil {
		return nil, errors.New("scanner is closed")
	}

	zoneParser := dns.NewZoneParser(zone, "", "")
	zoneParser.SetIncludeAllowed(true)

	var domains []string

	for tok, ok := zoneParser.Next(); ok; tok, ok = zoneParser.Next() {
		if tok.Header().Rrtype == dns.TypeNS {
			continue
		}

		domain := strings.Trim(tok.Header().Name, ".")
		if !strings.Contains(domain, ".") {
			// we have an NS record that serves as an anchor, and should skip it
			continue
		}

		domains = append(domains, domain)
	}

	return s.Scan(domains...)
}

// Close closes the scanner
func (s *Scanner) Close() {
	s.pool.Release()
	s.cache.Flush()
	s.logger.Debug().Msg("scanner closed")
}
