package scanner

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/miekg/dns"
)

const (
	DefaultBIMIPrefix = "v=BIMI1;"
	DefaultDKIMPrefix = "v=DKIM1;"
)

var (
	BIMIPrefix  = DefaultBIMIPrefix
	DKIMPrefix  = DefaultDKIMPrefix
	DMARCPrefix = regexp.MustCompile(`^v\s*=\s*DMARC1`) // Matches v=DMARC1 with whitespace (RFC7489).
	SPFPrefix   = regexp.MustCompile(`^v=(?i)spf1`)

	// knownDKIMSelectors is a list of known DKIM selectors.
	knownDKIMSelectors = []string{
		"x",             // Generic
		"google",        // Google
		"selector1",     // Microsoft
		"selector2",     // Microsoft
		"s1",            // Generic
		"s2",            // Generic
		"k1",            // MailChimp
		"mandrill",      // Mandrill
		"everlytickey1", // Everlytic
		"everlytickey2", // Everlytic
		"dkim",          // Hetzner
		"mxvault",       // MxVault
	}
)

// getDNSRecords queries the DNS server for records of a specific type for a domain.
// It returns a slice of strings (the records) and an error if any occurred.
func (s *Scanner) getDNSRecords(domain string, recordType uint16) ([]string, error) {
	answers, err := s.getDNSAnswers(domain, recordType)
	if err != nil {
		return nil, err
	}

	var records []string

	for _, answer := range answers {
		if answer.Header().Rrtype == dns.TypeCNAME {
			if t, ok := answer.(*dns.CNAME); ok {
				recursiveLookupTxt, err := s.getDNSRecords(t.Target, recordType)
				if err != nil {
					return nil, fmt.Errorf("recursively lookup txt record for %v: %w", t.Target, err)
				}

				records = append(records, recursiveLookupTxt...)

				continue
			}

			answer.Header().Rrtype = recordType
		}

		switch dnsRec := answer.(type) {
		case *dns.A:
			records = append(records, dnsRec.A.String())
		case *dns.AAAA:
			records = append(records, dnsRec.AAAA.String())
		case *dns.MX:
			records = append(records, dnsRec.Mx)
		case *dns.NS:
			records = append(records, dnsRec.Ns)
		case *dns.TXT:
			records = append(records, strings.Join(dnsRec.Txt, " "))
		}
	}

	return records, nil
}

// getDNSAnswers queries the DNS server for answers to a specific question.
// It returns a slice of dns.RR (DNS resource records) and an error if any occurred.
func (s *Scanner) getDNSAnswers(domain string, recordType uint16) ([]dns.RR, error) {
	req := &dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.SetEdns0(s.dnsBuffer, true) // increases the response buffer size
	req.SetQuestion(dns.Fqdn(domain), recordType)

	in, _, err := s.dnsClient.Exchange(req, s.getNS())
	if err != nil {
		return nil, fmt.Errorf("dns exchange: %w", err)
	}

	if in.Rcode != dns.RcodeSuccess {
		// Disregard NXDOMAIN errors.
		if in.Rcode == dns.RcodeNameError {
			return nil, nil
		}

		return nil, fmt.Errorf("DNS query failed with rcode %v", in.Rcode)
	}

	if in.MsgHdr.Truncated && s.dnsBuffer < 4096 {
		s.logger.Warn().Msg(fmt.Sprintf("DNS buffer %v was too small for %v, retrying with larger buffer (4096)", s.dnsBuffer, domain))

		req.SetEdns0(4096, true)

		in, _, err = s.dnsClient.Exchange(req, s.getNS())
		if err != nil {
			return nil, fmt.Errorf("dns exchange: %w", err)
		}
	}

	return in.Answer, nil
}

func (s *Scanner) getTypeBIMI(domain string) (string, error) {
	for _, dname := range []string{
		"default._bimi." + domain,
		domain,
	} {
		records, err := s.getDNSRecords(dname, dns.TypeTXT)
		if err != nil {
			return "", err
		}

		for index, record := range records {
			if strings.HasPrefix(record, BIMIPrefix) {
				// TXT records can be split across multiple strings, so we need to join them
				return strings.Join(records[index:], ""), nil
			}
		}
	}

	return "", nil
}

// getTypeDKIM queries the DNS server for DKIM records of a domain.
// It returns a string (DKIM record) and an error if any occurred.
func (s *Scanner) getTypeDKIM(domain string) (string, error) {
	selectors := append(s.dkimSelectors, knownDKIMSelectors...)

	// Some Microsoft domains (e.g. "onmicrosoft.com") use dynamic selectors.
	dashedDomain := strings.ReplaceAll(strings.ToLower(domain), ".", "-")
	selectors = append(selectors, "selector1-"+dashedDomain, "selector2-"+dashedDomain)

	for _, selector := range selectors {
		records, err := s.getDNSRecords(selector+"._domainkey."+domain, dns.TypeTXT)
		if err != nil {
			return "", err
		}

		for index, record := range records {
			if strings.HasPrefix(record, DKIMPrefix) {
				// TXT records can be split across multiple strings, we need to join them.
				return strings.Join(records[index:], ""), nil
			}
		}
	}

	return "", nil
}

// getTypeDMARC queries the DNS server for DMARC records of a domain.
// It returns a string (DMARC record) and an error if any occurred.
func (s *Scanner) getTypeDMARC(domain string) (string, error) {
	for _, dname := range []string{
		"_dmarc." + domain,
		domain,
	} {
		records, err := s.getDNSRecords(dname, dns.TypeTXT)
		if err != nil {
			return "", err
		}

		for index, record := range records {
			if DMARCPrefix.MatchString(record) {
				// TXT records can be split across multiple strings, we need to join them.
				return strings.Join(records[index:], ""), nil
			}
		}
	}

	return "", nil
}

// getTypeSPF queries the DNS server for SPF records of a domain.
// It returns a string (SPF record) and an error if any occurred.
func (s *Scanner) getTypeSPF(domain string) (string, error) {
	records, err := s.getDNSRecords(domain, dns.TypeTXT)
	if err != nil {
		return "", err
	}

	for _, record := range records {
		if SPFPrefix.MatchString(record) {
			if !strings.Contains(record, "redirect=") {
				return record, nil
			}

			parts := strings.Fields(record)
			for _, part := range parts {
				if strings.Contains(part, "redirect=") {
					redirectDomain := strings.TrimPrefix(part, "redirect=")
					return s.getTypeSPF(redirectDomain)
				}
			}
		}
	}

	return "", nil
}
