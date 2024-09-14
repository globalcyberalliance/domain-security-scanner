package mail

import (
	"bytes"
	"embed"
	"fmt"
	htmlTmpl "html/template"
	textTmpl "text/template"

	"github.com/GlobalCyberAlliance/domain-security-scanner/v3/pkg/model"
	"github.com/GlobalCyberAlliance/domain-security-scanner/v3/pkg/scanner"
)

var (
	//go:embed template.html
	htmlTemplateFile embed.FS

	//go:embed template.txt
	textTemplateFile embed.FS
)

func (s *Server) initializeTemplates() error {
	htmlTemplate, err := htmlTemplateFile.ReadFile("template.html")
	if err != nil {
		return fmt.Errorf("failed to read html template: %w", err)
	}

	templateHTML, err := htmlTmpl.New("html").Parse(string(htmlTemplate))
	if err != nil {
		return fmt.Errorf("failed to parse html template: %w", err)
	}

	textTemplate, err := textTemplateFile.ReadFile("template.txt")
	if err != nil {
		return fmt.Errorf("failed to read txt template: %w", err)
	}

	templateText, err := textTmpl.New("text").Parse(string(textTemplate))
	if err != nil {
		return fmt.Errorf("failed to parse txt template: %w", err)
	}

	s.templateHTML = templateHTML
	s.templateText = templateText

	return nil
}

func (s *Server) getMailContents(result model.ScanResultWithAdvice) (string, string, error) {
	var htmlBytes, textBytes bytes.Buffer

	if result.Advice == nil {
		result.Advice = &scanner.Advice{}
	}

	mailData := struct {
		AdviceDomain, AdviceBIMI, AdviceDKIM, AdviceDMARC, AdviceMX, AdviceSPF string
		ResultDomain, ResultBIMI, ResultDKIM, ResultDMARC, ResultMX, ResultSPF string
	}{
		AdviceDomain: stringify(result.Advice.Domain),
		AdviceBIMI:   stringify(result.Advice.BIMI),
		AdviceDKIM:   stringify(result.Advice.DKIM),
		AdviceDMARC:  stringify(result.Advice.DMARC),
		AdviceMX:     stringify(result.Advice.MX),
		AdviceSPF:    stringify(result.Advice.SPF),
		ResultDomain: result.ScanResult.Domain,
		ResultBIMI:   result.ScanResult.BIMI,
		ResultDKIM:   result.ScanResult.DKIM,
		ResultDMARC:  result.ScanResult.DMARC,
		ResultMX:     stringify(result.ScanResult.MX),
		ResultSPF:    result.ScanResult.SPF,
	}

	// prevent template errors
	if result.Advice == nil {
		result.Advice = &scanner.Advice{}
	}

	if err := s.templateHTML.Execute(&htmlBytes, mailData); err != nil {
		return "", "", fmt.Errorf("failed to execute html template: %w", err)
	}

	if err := s.templateText.Execute(&textBytes, mailData); err != nil {
		return "", "", fmt.Errorf("failed to execute text template: %w", err)
	}

	return htmlBytes.String(), textBytes.String(), nil
}
