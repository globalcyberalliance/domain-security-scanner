package mail

import (
	"context"
	"fmt"
	htmlTmpl "html/template"
	textTmpl "text/template"
	"time"

	domainAdvisor "github.com/globalcyberalliance/domain-security-scanner/v3/pkg/advisor"
	"github.com/globalcyberalliance/domain-security-scanner/v3/pkg/cache"
	"github.com/globalcyberalliance/domain-security-scanner/v3/pkg/model"
	"github.com/globalcyberalliance/domain-security-scanner/v3/pkg/scanner"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/spf13/cast"
)

type Server struct {
	advisor      *domainAdvisor.Advisor
	config       Config
	cooldown     *cache.Cache[string]
	interval     time.Duration
	logger       zerolog.Logger
	templateHTML *htmlTmpl.Template
	templateText *textTmpl.Template
	CheckTLS     bool
	Scanner      *scanner.Scanner
}

// NewMailServer returns a new instance of a mail server.
func NewMailServer(config Config, logger zerolog.Logger, sc *scanner.Scanner, advisor *domainAdvisor.Advisor) (*Server, error) {
	s := Server{
		advisor:  advisor,
		config:   config,
		cooldown: cache.New[string](1 * time.Minute),
		logger:   logger,
		Scanner:  sc,
	}

	client, err := s.Login()
	if err != nil {
		return nil, err
	}
	defer client.Logout()

	if err = s.initializeTemplates(); err != nil {
		return nil, fmt.Errorf("initialize mail templates: %w", err)
	}

	return &s, nil
}

func (s *Server) Serve(interval time.Duration) {
	s.interval = interval

	s.logger.Info().Msg("Starting mail server on mailbox " + s.config.Inbound.User)
	s.logger.Info().Msg("Mail check interval set to " + cast.ToString(interval))

	if err := s.handler(); err != nil {
		s.logger.Fatal().Err(err).Msg("An error occurred while hosting the mail server")
	}
}

func (s *Server) handler() error {
	ticker := time.NewTicker(s.interval)
	quit := make(chan struct{})
	for {
		select {
		case <-ticker.C:
			s.logger.Debug().Msg("Checking for mail")

			addresses, err := s.GetMail()
			if err != nil && err.Error() != "no new messages" {
				s.logger.Error().Err(err).Msg("Could not obtain the latest mail from mail server")
			}

			var dkimSelectors, domainList []string
			for domain := range addresses {
				cooldownDomain := s.cooldown.Get(domain)
				if cooldownDomain != nil {
					continue
				}

				s.cooldown.Set(domain, &domain)

				if addresses[domain].DKIMSelector != "" {
					dkimSelectors = append(dkimSelectors, addresses[domain].DKIMSelector)
				}

				domainList = append(domainList, domain)
			}

			if len(domainList) == 0 {
				continue
			}

			if len(dkimSelectors) > 0 {
				if err = s.Scanner.OverwriteOption(scanner.WithDKIMSelectors(dkimSelectors...)); err != nil {
					s.logger.Error().Err(err).Msg("Failed to override DKIM selectors for mail")
				}
			}

			results, err := s.Scanner.Scan(context.Background(), domainList...)
			if err != nil {
				s.logger.Error().Err(err).Msg("An error occurred while scanning domains")
				continue
			}

			for _, result := range results {
				sender := addresses[result.Domain].Address

				resultWithAdvice := model.ScanResultWithAdvice{
					ScanResult: result,
				}

				if s.advisor != nil || result.Error != scanner.ErrInvalidDomain {
					resultWithAdvice.Advice = s.advisor.CheckAll(result.Domain, result.BIMI, result.DKIM, result.DMARC, result.MX, result.SPF)
				}

				if err = s.SendMail(sender, resultWithAdvice); err != nil {
					s.logger.Error().Err(err).Msg("An error occurred while sending scan results to " + sender)
					continue
				}

				s.logger.Info().Msg("Sent results to " + sender)
			}
		case <-quit:
			ticker.Stop()
			return errors.New("server manually stopped")
		}
	}
}
