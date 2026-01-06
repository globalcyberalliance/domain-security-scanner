package scanner

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// OverwriteOption allows the caller to overwrite an existing option.
func (s *Scanner) OverwriteOption(option Option) error {
	if option == nil {
		return errors.New("invalid option")
	}

	return option(s)
}

// WithCacheDuration sets the duration that a cache entry will be valid for.
func WithCacheDuration(duration time.Duration) Option {
	return func(s *Scanner) error {
		s.cacheDuration = duration
		return nil
	}
}

// WithConcurrentScans sets the number of entities that will be scanned
// concurrently.
//
// If n <= 0, then this option will default to the return value of
// runtime.NumCPU().
func WithConcurrentScans(quota uint16) Option {
	return func(s *Scanner) error {
		if quota <= 0 {
			quota = uint16(runtime.NumCPU())
		}

		s.poolSize = quota

		return nil
	}
}

// WithDKIMSelectors allows the caller to specify which DKIM selectors to
// scan for (falling back to the default selectors if none are provided).
func WithDKIMSelectors(selectors ...string) Option {
	return func(s *Scanner) error {
		if len(selectors) == 0 {
			return errors.New("no DKIM selectors provided")
		}

		// validate DKIM selectors
		for _, selector := range selectors {
			if err := validateDKIMSelector(selector); err != nil {
				return fmt.Errorf("invalid DKIM selector: %w", err)
			}
		}

		s.dkimSelectors = selectors

		return nil
	}
}

// WithDNSBuffer increases the allocated buffer for DNS responses.
func WithDNSBuffer(bufferSize uint16) Option {
	return func(s *Scanner) error {
		if bufferSize <= 0 {
			return fmt.Errorf("invalid DNS buffer size: %d", bufferSize)
		}

		s.dnsBuffer = bufferSize

		return nil
	}
}

// WithDNSProtocol sets the DNS protocol to use for queries.
func WithDNSProtocol(protocol string) Option {
	return func(s *Scanner) error {
		protocol = strings.ToLower(protocol)

		switch protocol {
		case "udp", "tcp", "tcp-tls":
			s.dnsClient.Net = protocol
		default:
			return fmt.Errorf("invalid DNS protocol: %s, valid options: udp, tcp, tcp-tls", protocol)
		}

		return nil
	}
}

// WithNameservers allows the caller to provide a custom set of nameservers for a *Scanner to use. If ns is nil, or
// zero-length, the *Scanner will use the nameservers specified in /etc/resolv.conf.
func WithNameservers(nameservers []string) Option {
	return func(s *Scanner) error {
		// If the provided slice of nameservers is nil, or has zero elements, load up /etc/resolv.conf, and get the
		// "index" directives from there.
		if len(nameservers) == 0 {
			// Check if /etc/resolv.conf exists.
			config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
			if err != nil {
				// If /etc/resolv.conf does not exist, use Google and Cloudflare.
				s.nameservers = []string{"8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53"}
				return nil
			}

			nameservers = config.Servers
		}

		// Make sure each of the nameservers is in the "host:port" format.
		//
		// The "dns" package requires that you explicitly state the port number for the resolvers that get queried.
		for index := range nameservers {
			addr, err := netip.ParseAddr(nameservers[index])
			if err != nil {
				// The nameserver might contain a port.
				host, port, err := net.SplitHostPort(nameservers[index])
				if err != nil {
					return fmt.Errorf("invalid IP address: %s", nameservers[index])
				}

				// Validate the IP.
				addr, err = netip.ParseAddr(host)
				if err != nil {
					return fmt.Errorf("invalid IP address: %s", nameservers[index])
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

		s.nameservers = nameservers

		return nil
	}
}

func validateDKIMSelector(selector string) error {
	switch {
	case len(selector) == 0:
		return errors.New("DKIM selector is empty")
	case len(selector) > 63:
		return fmt.Errorf("DKIM selector length is %d, can't exceed 63", len(selector))
	case selector[0] == '.' || selector[0] == '_':
		return fmt.Errorf("DKIM selector should not start with '%c'", selector[0])
	case selector[len(selector)-1] == '.' || selector[len(selector)-1] == '_':
		return fmt.Errorf("DKIM selector should not end with '%c'", selector[len(selector)-1])
	}

	for i, char := range selector {
		if !regexp.MustCompile(`^[a-zA-Z0-9\-\._]$`).MatchString(string(char)) {
			return fmt.Errorf("DKIM selector has invalid character '%c' at offset %d", char, i)
		}
	}

	return nil
}
