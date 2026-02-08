package main

import (
	"bufio"
	"os"

	"github.com/globalcyberalliance/domain-security-scanner/v3/pkg/advisor"
	"github.com/globalcyberalliance/domain-security-scanner/v3/pkg/model"
	"github.com/globalcyberalliance/domain-security-scanner/v3/pkg/scanner"
	"github.com/spf13/cobra"
)

func newScanCMD() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "scan [flags] <STDIN>",
		Example: "  dss scan <STDIN>\n  dss scan globalcyberalliance.org gcaaide.org google.com\n  dss scan -z < zonefile",
		Short:   "Scan DNS records for one or multiple domains.",
		Long:    "Scan DNS records for one or multiple domains.\nBy default, the command will listen on STDIN, allowing you to type or pipe multiple domains.",
		Run: func(cmd *cobra.Command, args []string) {
			sc, err := scanner.New(log, timeout, getScannerOpts()...)
			if err != nil {
				log.Fatal().Err(err).Msg("An unexpected error occurred.")
			}

			domainAdvisor := advisor.NewAdvisor(timeout, cache, checkTLS)

			var results []*scanner.Result

			if len(args) == 0 && zoneFile {
				results, err = sc.ScanZone(os.Stdin)
				if err != nil {
					log.Fatal().Err(err).Msg("An unexpected error occurred.")
				}

				var resultsWithAdvice []model.ScanResultWithAdvice
				for _, result := range results {
					resultsWithAdvice = append(resultsWithAdvice, getResultWithAdvice(result, domainAdvisor))
				}
				printToConsole(resultsWithAdvice)
			} else if len(args) > 0 && zoneFile {
				log.Fatal().Msg("-z flag provided, but not reading from STDIN")
			} else if len(args) == 0 {
				fi, err := os.Stdin.Stat()
				if err != nil {
					log.Fatal().Err(err).Msg("Failed to stat input")
				}

				// avoid logging if input is a pipe.
				if (fi.Mode() & os.ModeCharDevice) != 0 {
					log.Info().Msg("Enter one or more domains to scan (press Ctrl-C to finish):")
				}

				lineScanner := bufio.NewScanner(os.Stdin)

				var resultsWithAdvice []model.ScanResultWithAdvice
				for lineScanner.Scan() {
					domain := lineScanner.Text()

					results, err = sc.Scan(cmd.Context(), domain)
					if err != nil {
						log.Fatal().Err(err).Msg("An unexpected error occurred.")
					}

					for _, result := range results {
						resultsWithAdvice = append(resultsWithAdvice, getResultWithAdvice(result, domainAdvisor))
					}
				}

				if err = lineScanner.Err(); err != nil {
					log.Fatal().Err(err).Msg("An error occurred while reading from stdin.")
				}

				if len(resultsWithAdvice) > 0 {
					printToConsole(resultsWithAdvice)
				}
			} else {
				results, err = sc.Scan(cmd.Context(), args...)
				if err != nil {
					log.Fatal().Err(err).Msg("An unexpected error occurred.")
				}

				var resultsWithAdvice []model.ScanResultWithAdvice
				for _, result := range results {
					resultsWithAdvice = append(resultsWithAdvice, getResultWithAdvice(result, domainAdvisor))
				}

				printToConsole(resultsWithAdvice)
			}
		},
	}

	return cmd
}

func getResultWithAdvice(result *scanner.Result, domainAdvisor *advisor.Advisor) model.ScanResultWithAdvice {
	if result == nil {
		log.Fatal().Msg("An unexpected error occurred.")
	}

	resultWithAdvice := model.ScanResultWithAdvice{
		ScanResult: result,
	}

	if advise && result.Error != scanner.ErrInvalidDomain {
		resultWithAdvice.Advice = domainAdvisor.CheckAll(result.Domain, result.BIMI, result.DKIM, result.DMARC, result.MX, result.SPF)
	}

	return resultWithAdvice
}
