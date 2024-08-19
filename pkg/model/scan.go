package model

import (
	"strings"

	"github.com/GlobalCyberAlliance/domain-security-scanner/v3/pkg/scanner"
)

type ScanResultWithAdvice struct {
	ScanResult *scanner.Result `json:"scanResult" yaml:"scanResult" doc:"The results of scanning a domain's DNS records."`
	Advice     *scanner.Advice `json:"advice,omitempty" yaml:"advice,omitempty" doc:"The advice for the domain's DNS records."`
}

func (s *ScanResultWithAdvice) CSV() []string {
	var advice string

	for _, value := range s.Advice.Domain {
		advice += "Domain: " + value + "; "
	}

	for _, value := range s.Advice.BIMI {
		advice += "BIMI: " + value + "; "
	}

	for _, value := range s.Advice.DKIM {
		advice += "DKIM: " + value + "; "
	}

	for _, value := range s.Advice.DMARC {
		advice += "DMARC: " + value + "; "
	}

	for _, value := range s.Advice.MX {
		advice += "MX: " + value + "; "
	}

	for _, value := range s.Advice.SPF {
		advice += "SPF: " + value + "; "
	}

	return []string{s.ScanResult.Domain, s.ScanResult.BIMI, s.ScanResult.DKIM, s.ScanResult.DMARC, strings.Join(s.ScanResult.MX, "; "), s.ScanResult.SPF, s.ScanResult.Error, advice}
}
