package dns

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/miekg/dns"
)

const (
	DefaultBIMIPrefix  = "v=BIMI1;"
	DefaultDKIMPrefix  = "v=DKIM1;"
	DefaultDMARCPrefix = "v=DMARC1;"
	DefaultSPFPrefix   = "v=spf1 "
	DefaultSTSPrefix   = "v=STSv1;"
)

var (
	BIMIPrefix  = DefaultBIMIPrefix
	DKIMPrefix  = DefaultDKIMPrefix
	DMARCPrefix = DefaultDMARCPrefix
	SPFPrefix   = DefaultSPFPrefix
	STSPrefix   = DefaultSTSPrefix

	// knownDkimSelectors is a list of known DKIM selectors.
	knownDkimSelectors = []string{
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

	dnssecTypes = map[uint16]string{
		dns.TypeDNSKEY:  "DNSKEY",
		dns.TypeRRSIG:   "RRSIG",
		dns.TypeDS:      "DS",
		dns.TypeNSEC:    "NSEC",
		dns.TypeNSEC3:   "NSEC3",
		dns.TypeCDNSKEY: "CDNSKEY",
		dns.TypeCDS:     "CDS",
	}

	reverseDnssecTypes = map[uint16]string{}
)

// TODO: we no longer disregard NXDOMAIN requests. This should be handled downstream.

func (s *Client) Scan(domain string, recordType uint16, recursiveLookup ...bool) ([]string, error) {
	recursion := true
	if len(recursiveLookup) > 0 && recursiveLookup[0] == false {
		recursion = false
	}

	return s.getDNSRecords(domain, recordType, recursion)
}

// getDNSRecords queries the DNS server for records of a specific type for a domain.
// It returns a slice of strings (the records) and an error if any occurred.
func (s *Client) getDNSRecords(domain string, recordType uint16, recursion bool) (records []string, err error) {
	answers, err := s.GetDNSAnswers(domain, recordType)
	if err != nil {
		return nil, err
	}

	if _, ok := dnssecTypes[recordType]; ok {
		for _, answer := range answers {
			// records = append(records, strings.TrimPrefix(answer.String(), answer.Header().String()))
			records = append(records, answer.String())
		}
		return records, nil
	}

	for _, answer := range answers {

		// Recursively lookup the CNAME record until we reach the underlying DNS record.
		if recursion && answer.Header().Rrtype == dns.TypeCNAME {
			if t, ok := answer.(*dns.CNAME); ok {
				recursiveLookupTxt, err := s.getDNSRecords(t.Target, recordType, recursion)
				if err != nil {
					return nil, fmt.Errorf("failed to recursively lookup txt record for %v: %w", t.Target, err)
				}

				records = append(records, recursiveLookupTxt...)

				continue
			}

			answer.Header().Rrtype = recordType
		}

		switch record := answer.(type) {
		case *dns.A:
			records = append(records, record.A.String())
		case *dns.AAAA:
			records = append(records, record.AAAA.String())
		case *dns.CNAME:
			records = append(records, record.String())
		case *dns.MX:
			records = append(records, record.Mx)
		case *dns.NS:
			records = append(records, record.Ns)
		case *dns.TXT:
			records = append(records, record.Txt...)
		}
	}

	return records, nil
}

// GetDNSAnswers queries the DNS server for answers to a specific question.
// It returns a slice of dns.RR (DNS resource records) and an error if any occurred.
func (s *Client) GetDNSAnswers(domain string, recordType uint16) ([]dns.RR, error) {
	req := &dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.SetEdns0(s.Buffer, true) // Specify the buffer size.
	req.SetQuestion(dns.Fqdn(domain), recordType)

	in, _, err := s.client.Exchange(req, s.getNS())
	if err != nil {
		return nil, err
	}

	if in.Rcode != dns.RcodeSuccess {
		if in.Rcode == dns.RcodeNameError {
			return nil, nil
		}

		return nil, fmt.Errorf("DNS query failed with rcode %v", in.Rcode)
	}

	if in.MsgHdr.Truncated {
		return nil, fmt.Errorf("DNS buffer %v was too small", s.Buffer)
	}

	return in.Answer, nil
}

func (s *Client) GetTypeBIMI(domain string) (string, error) {
	for _, dname := range []string{
		"default._bimi." + domain,
		domain,
	} {
		records, err := s.getDNSRecords(dname, dns.TypeTXT, true)
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
func (s *Client) GetTypeDKIM(domain string) (string, error) {
	selectors := append(s.DkimSelectors, knownDkimSelectors...)

	for _, selector := range selectors {
		records, err := s.getDNSRecords(selector+"._domainkey."+domain, dns.TypeTXT, true)
		if err != nil {
			return "", err
		}

		for index, record := range records {
			if strings.HasPrefix(record, DKIMPrefix) {
				// TXT records can be split across multiple strings, so we need to join them
				return strings.Join(records[index:], ""), nil
			}
		}
	}

	return "", nil
}

// getTypeDMARC queries the DNS server for DMARC records of a domain.
// It returns a string (DMARC record) and an error if any occurred.
func (s *Client) GetTypeDMARC(domain string) (string, error) {
	for _, dname := range []string{
		"_dmarc." + domain,
		domain,
	} {
		records, err := s.getDNSRecords(dname, dns.TypeTXT, true)
		if err != nil {
			return "", err
		}

		for index, record := range records {
			if strings.HasPrefix(record, DMARCPrefix) {
				// TXT records can be split across multiple strings, so we need to join them
				return strings.Join(records[index:], ""), nil
			}
		}
	}

	return "", nil
}

// getTypeSPF queries the DNS server for SPF records of a domain.
// It returns a string (SPF record) and an error if any occurred.
func (s *Client) GetTypeSPF(domain string) (string, error) {
	records, err := s.getDNSRecords(domain, dns.TypeTXT, true)
	if err != nil {
		return "", err
	}

	for _, record := range records {
		if strings.HasPrefix(record, SPFPrefix) {
			if !strings.Contains(record, "redirect=") {
				return record, nil
			}

			parts := strings.Fields(record)
			for _, part := range parts {
				if strings.Contains(part, "redirect=") {
					redirectDomain := strings.TrimPrefix(part, "redirect=")
					return s.GetTypeSPF(redirectDomain)
				}
			}
		}
	}

	return "", nil
}

// getTypeSPF queries the DNS server for SPF records of a domain.
// It returns a string (SPF record) and an error if any occurred.
func (s *Client) GetTypeMX(domain string) ([]string, error) {
	records, err := s.getDNSRecords(domain, dns.TypeMX, true)
	if err != nil {
		return nil, err
	}

	return records, nil
}

func (s *Client) GetTypeNS(domain string) ([]string, error) {
	records, err := s.getDNSRecords(domain, dns.TypeNS, true)
	if err != nil {
		return nil, err
	}

	return records, nil
}

func (s *Client) GetTypeSTS(domain string) (string, string, error) {
	for _, dname := range []string{
		"_mta-sts." + domain,
		domain,
	} {
		records, err := s.getDNSRecords(dname, dns.TypeTXT, true)
		if err != nil {
			return "", "", err
		}

		for index, record := range records {
			if strings.HasPrefix(record, STSPrefix) {
				// TXT records can be split across multiple strings, so we need to join them
				response, err := http.Get("https://mta-sts." + domain + "/.well-known/mta-sts.txt")
				if err != nil {
					return "", "", err
				}

				if response.StatusCode != http.StatusOK {
					return "", "", fmt.Errorf("failed to get mta-sts record for %v: %v", domain, response.Status)
				}

				policy, err := io.ReadAll(response.Body)
				if err != nil {
					return "", "", err
				}
				cleanPolicy := strings.ReplaceAll(string(policy), "\r\n", "\n")
				return strings.Join(records[index:], ""), cleanPolicy, nil
			}
		}
	}

	return "", "", nil
}

func (s *Client) GetTypeDNSSEC(domain string) (string, error) {
	var dnssecInfo string
	var errorMessages []string

	for recordType, recordName := range dnssecTypes {
		records, err := s.getDNSRecords(domain, recordType, true)
		if err != nil {
			errorMessages = append(errorMessages, fmt.Sprintf("failed to query %s: %v\n", recordName, err))
			continue
		}

		for index, record := range records {
			// fmt.Println("Whole record :", record)
			// for _, term := range strings.Split(record, "\n") {
			// fmt.Println("line: ", term)

			//for _, word := range strings.Fields(term) {
			//fmt.Println("word: ", word)
			//}
			//}
			// remove domain, TTL, class, and raw data digest
			dnssecInfo += fmt.Sprintf(" %s-%d: %v\n", recordName, index+1, record)
			if record == "" {
				fmt.Println("Empty record")
			}
		}
	}
	if len(errorMessages) == 0 {
		return dnssecInfo, nil
	}
	return dnssecInfo, fmt.Errorf("some DNSSEC record queries failed:\n%s", strings.Join(errorMessages, "\n"))
}
