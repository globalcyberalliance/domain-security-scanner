package http

import (
	"context"
	"fmt"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/globalcyberalliance/domain-security-scanner/v3/pkg/model"
	"github.com/globalcyberalliance/domain-security-scanner/v3/pkg/scanner"
)

func (s *Server) registerScanRoutes() {
	type ScanSingleDomainRequest struct {
		DKIMSelectors []string `query:"dkimSelectors" maxItems:"5" example:"selector1,selector2" doc:"Specify custom DKIM selectors"`
		Domain        string   `path:"domain" maxLength:"255" example:"example.com" doc:"Domain to scan"`
	}

	type ScanSingleDomainResponse struct {
		Body struct{ model.ScanResultWithAdvice }
	}

	huma.Register(s.router, huma.Operation{
		OperationID: "scan-domain",
		Summary:     "Scan a single domain",
		Method:      http.MethodGet,
		Path:        s.apiPath + "/scan/{domain}",
		Tags:        []string{"Scan Domains"},
	}, func(ctx context.Context, input *ScanSingleDomainRequest) (*ScanSingleDomainResponse, error) {
		resp := ScanSingleDomainResponse{}

		if len(input.DKIMSelectors) > 0 {
			if err := s.Scanner.OverwriteOption(scanner.WithDKIMSelectors(input.DKIMSelectors...)); err != nil {
				return nil, huma.Error500InternalServerError(err.Error())
			}
		}

		results, err := s.Scanner.Scan(input.Domain)
		if err != nil {
			return nil, huma.Error500InternalServerError(err.Error())
		}

		if len(results) != 1 {
			return nil, huma.Error500InternalServerError(fmt.Errorf("expected 1 result, got %d", len(results)).Error())
		}

		if results[0].Error == scanner.ErrInvalidDomain {
			return nil, huma.Error400BadRequest(scanner.ErrInvalidDomain)
		}

		result := model.ScanResultWithAdvice{
			ScanResult: results[0],
		}

		if s.Advisor != nil {
			result.Advice = s.Scanner.CheckAll(result.ScanResult.Domain, result.ScanResult.BIMI, result.ScanResult.DKIM, result.ScanResult.DMARC, result.ScanResult.MX, result.ScanResult.SPF, result.ScanResult.STS, result.ScanResult.STSPolicy, result.ScanResult.DNSSEC)
		}

		resp.Body.ScanResultWithAdvice = result

		return &resp, nil
	})

	type ScanBulkDomainsRequest struct {
		DKIMSelectors []string `query:"dkimSelectors" maxItems:"5" example:"selector1,selector2" doc:"Specify custom DKIM selectors"`
		Body          struct {
			Domains []string `json:"domains" maxItems:"20" doc:"Domains to scan. Max 20 domains at a time." example:"example.com"`
		}
	}

	type ScanBulkDomainResponse struct {
		Body struct {
			Results []model.ScanResultWithAdvice `json:"results" doc:"The results of scanning the domains."`
		}
	}

	huma.Register(s.router, huma.Operation{
		OperationID: "scan-domains",
		Summary:     "Scan multiple domains",
		Method:      http.MethodPost,
		Path:        s.apiPath + "/scan",
		Tags:        []string{"Scan Domains"},
	}, func(ctx context.Context, input *ScanBulkDomainsRequest) (*ScanBulkDomainResponse, error) {
		resp := ScanBulkDomainResponse{}

		results, err := s.Scanner.Scan(input.Body.Domains...)
		if err != nil {
			return nil, huma.Error500InternalServerError(err.Error())
		}

		if len(results) == 0 {
			return nil, huma.Error500InternalServerError("no results found")
		}

		for _, result := range results {
			res := model.ScanResultWithAdvice{
				ScanResult: result,
			}

			if s.Advisor != nil && result.Error != scanner.ErrInvalidDomain {
				res.Advice = s.Scanner.CheckAll(result.Domain, result.BIMI, result.DKIM, result.DMARC, result.MX, result.SPF, result.STS, result.STSPolicy, result.DNSSEC)
			}

			resp.Body.Results = append(resp.Body.Results, res)
		}

		return &resp, nil
	})
}
