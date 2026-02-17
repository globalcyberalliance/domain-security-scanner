package model

import (
	"strings"

	"github.com/globalcyberalliance/domain-security-scanner/v3/pkg/advisor"
	"github.com/globalcyberalliance/domain-security-scanner/v3/pkg/scanner"
)

type ScanResultWithAdvice struct {
	ScanResult *scanner.Result `json:"scanResult" yaml:"scanResult" doc:"The results of scanning a domain's DNS records."`
	Advice     *advisor.Advice `json:"advice,omitempty" yaml:"advice,omitempty" doc:"The advice for the domain's DNS records."`
}

func (s *ScanResultWithAdvice) CSV() []string {
	var advice strings.Builder

	if s.Advice != nil {
		for _, value := range s.Advice.Domain {
			advice.WriteString("Domain: " + value + "; ")
		}

		for _, value := range s.Advice.BIMI {
			advice.WriteString("BIMI: " + value + "; ")
		}

		for _, value := range s.Advice.DKIM {
			advice.WriteString("DKIM: " + value + "; ")
		}

		for _, value := range s.Advice.DMARC {
			advice.WriteString("DMARC: " + value + "; ")
		}

		for _, value := range s.Advice.MX {
			advice.WriteString("MX: " + value + "; ")
		}

		for _, value := range s.Advice.SPF {
			advice.WriteString("SPF: " + value + "; ")
		}
	}

	return []string{s.ScanResult.Domain, s.ScanResult.BIMI, s.ScanResult.DKIM, s.ScanResult.DMARC, strings.Join(s.ScanResult.MX, "; "), s.ScanResult.SPF, s.ScanResult.Error, advice.String()}
}
