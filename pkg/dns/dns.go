package dns

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const (
	TypeA     = dns.TypeA
	TypeAAAA  = dns.TypeAAAA
	TypeCNAME = dns.TypeCNAME
	TypeMX    = dns.TypeMX
	TypeNS    = dns.TypeNS
	TypeTXT   = dns.TypeTXT
	TypeSRV   = dns.TypeSRV
)

func NewZoneParser(r io.Reader, origin, file string) *dns.ZoneParser {
	return dns.NewZoneParser(r, origin, file)
}

type (
	Client struct {
		// buffer is used to configure the size of the buffer allocated for DNS responses.
		Buffer uint16

		// client is the underlying DNS client used for scans.
		client *dns.Client

		// The index of the last-used nameserver, from the nameservers slice.
		//
		// This field is managed by atomic operations, and should only ever be referenced by the (*Client).getNS()
		// method.
		lastNameserverID uint32

		// Nameservers is a slice of "host:port" strings of nameservers to issue queries against.
		Nameservers []string

		// Protocol is used to track the initialized protocol, e.g. UDP or TCP.
		Protocol string

		DKIMSelectors []string
	}
)

func New(timeout time.Duration, buffer uint16, protocol string, nameservers ...string) (*Client, error) {
	if timeout <= 0 {
		return nil, errors.New("timeout must be greater than 0")
	}

	if buffer <= 0 {
		buffer = 4096
	}

	switch protocol {
	case "":
		protocol = "udp"
	case "udp", "tcp", "tcp-tls":
	default:
		return nil, fmt.Errorf("invalid DNS protocol: %s, valid options: udp, tcp, tcp-tls", protocol)
	}

	parsedNameservers, err := ParseNameservers(nameservers)
	if err != nil {
		return nil, fmt.Errorf("failed to parse nameservers: %w", err)
	}

	client := new(dns.Client)
	client.Net = protocol
	client.Timeout = timeout

	return &Client{
		Buffer:      buffer,
		client:      client,
		Nameservers: parsedNameservers,
	}, nil
}

func (s *Client) getNS() string {
	return s.Nameservers[int(atomic.AddUint32(&s.lastNameserverID, 1))%len(s.Nameservers)]
}

func ParseNameservers(nameservers []string) ([]string, error) {
	// If the provided slice of nameservers is nil, or has zero
	// elements, load up /etc/resolv.conf, and get the "index"
	// directives from there.
	if len(nameservers) == 0 {
		// Check if /etc/resolv.conf exists.
		config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			// If /etc/resolv.conf does not exist, use Google and Cloudflare.
			return []string{"8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53"}, nil
		}

		nameservers = config.Servers
	}

	// Make sure each of the nameservers is in the "host:port" format.
	//
	// The "dns" package requires that you explicitly state the port
	// number for the resolvers that get queried.
	for index := range nameservers {
		addr, err := netip.ParseAddr(nameservers[index])
		if err != nil {
			// Might contain a port.
			host, port, err := net.SplitHostPort(nameservers[index])
			if err != nil {
				return nil, fmt.Errorf("invalid IP address: %s", nameservers[index])
			}

			// Validate IP.
			addr, err = netip.ParseAddr(host)
			if err != nil {
				return nil, fmt.Errorf("invalid IP address: %s", nameservers[index])
			}

			if addr.Is6() {
				nameservers[index] = fmt.Sprintf("[%s]:%v", addr.String(), port)
			} else {
				nameservers[index] = fmt.Sprintf("%s:%v", addr.String(), port)
			}

			continue
		}

		if addr.Is6() {
			nameservers[index] = fmt.Sprintf("[%s]:53", addr.String())
		} else {
			nameservers[index] = fmt.Sprintf("%s:53", addr.String())
		}
	}

	return nameservers, nil
}

// ParseZone parses a zone file and returns the found domains.
func ParseZone(zone io.Reader) []string {
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

	return domains
}
