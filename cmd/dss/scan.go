package main

import (
	"bufio"
	"os"

	"github.com/GlobalCyberAlliance/domain-security-scanner/v3/pkg/model"
	"github.com/GlobalCyberAlliance/domain-security-scanner/v3/pkg/scanner"
	"github.com/spf13/cobra"
)

func init() {
	cmd.AddCommand(cmdScan)
}

var cmdScan = &cobra.Command{
	Use:     "scan [flags] <STDIN>",
	Example: "  dss scan <STDIN>\n  dss scan globalcyberalliance.org gcaaide.org google.com\n  dss scan -z < zonefile",
	Short:   "Scan DNS records for one or multiple domains.",
	Long:    "Scan DNS records for one or multiple domains.\nBy default, the command will listen on STDIN, allowing you to type or pipe multiple domains.",
	Run: func(command *cobra.Command, args []string) {
		opts := []scanner.Option{
			scanner.WithCacheDuration(cache),
			scanner.WithConcurrentScans(concurrent),
			scanner.WithDNSBuffer(dnsBuffer),
			scanner.WithDNSProtocol(dnsProtocol),
			scanner.WithNameservers(nameservers),
			scanner.WithCheckTLS(checkTLS),
		}

		if len(dkimSelector) > 0 {
			opts = append(opts, scanner.WithDKIMSelectors(dkimSelector...))
		}
		sc, err := scanner.New(log, timeout, opts...)
		if err != nil {
			log.Fatal().Err(err).Msg("An unexpected error occurred.")
		}

		if format == "csv" && outputFile == "" {
			log.Info().Msg("CSV header: domain,BIMI,DKIM,DMARC,MX,SPF,TXT,error,advice")
		}

		var results []*scanner.Result

		if len(args) == 0 && zoneFile {
			results, err = sc.ScanZone(os.Stdin)
			if err != nil {
				log.Fatal().Err(err).Msg("An unexpected error occurred.")
			}
		} else if len(args) > 0 && zoneFile {
			log.Fatal().Msg("-z flag provided, but not reading from STDIN")
		} else if len(args) == 0 {
			log.Info().Msg("Enter one or more domains to scan (press Ctrl-C to finish):")

			scanner := bufio.NewScanner(os.Stdin)

			for scanner.Scan() {
				domain := scanner.Text()
				results, err = sc.Scan(domain)
				if err != nil {
					log.Fatal().Err(err).Msg("An unexpected error occurred.")
				}

				for _, result := range results {
					printResult(result, sc)
				}
			}

			if err = scanner.Err(); err != nil {
				log.Fatal().Err(err).Msg("An error occurred while reading from stdin.")
			}
		} else {
			results, err = sc.Scan(args...)
			if err != nil {
				log.Fatal().Err(err).Msg("An unexpected error occurred.")
			}
		}

		if err != nil {
			log.Fatal().Err(err).Msg("An unexpected error occurred.")
		}

		for _, result := range results {
			printResult(result, sc)
		}
	},
}

func printResult(result *scanner.Result, s *scanner.Scanner) {
	if result == nil {
		log.Fatal().Msg("An unexpected error occurred.")
	}

	resultWithAdvice := model.ScanResultWithAdvice{
		ScanResult: result,
	}

	if advise && result.Error != scanner.ErrInvalidDomain {
		resultWithAdvice.Advice = s.CheckAll(result.Domain, result.BIMI, result.DKIM, result.DMARC, result.MX, result.SPF, result.STS, result.STSPolicy, result.DNSSEC)
	}

	printToConsole(resultWithAdvice)
}
