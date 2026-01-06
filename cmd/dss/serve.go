package main

import (
	"time"

	"github.com/globalcyberalliance/domain-security-scanner/v3/pkg/advisor"
	"github.com/globalcyberalliance/domain-security-scanner/v3/pkg/http"
	"github.com/globalcyberalliance/domain-security-scanner/v3/pkg/mail"
	"github.com/globalcyberalliance/domain-security-scanner/v3/pkg/scanner"
	"github.com/spf13/cobra"
)

var (
	interval        time.Duration
	mailConfig      mail.Config
	port, rateLimit int
)

func newServeCMD() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the scanner via a REST API or dedicated mailbox",
		Run: func(command *cobra.Command, _ []string) {
			_ = command.Help()
		},
	}

	cmd.AddCommand(newServeAPICMD())
	cmd.AddCommand(newServeMailCMD())

	return cmd
}

func newServeAPICMD() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "api",
		Short: "Serve DNS security queries via a dedicated API",
		Run: func(_ *cobra.Command, _ []string) {
			sc, err := scanner.New(log, timeout, getScannerOpts()...)
			if err != nil {
				log.Fatal().Err(err).Msg("Could not create domain scanner")
			}

			server := http.NewServer(log, timeout, rateLimit, version)
			if advise {
				server.Advisor = advisor.NewAdvisor(timeout, cache, checkTLS)
			}
			server.CheckTLS = checkTLS
			server.Scanner = sc

			server.Serve(port)
		},
	}

	cmd.Flags().IntVarP(&port, "port", "p", 8080, "Specify the port for the API to listen on")
	cmd.Flags().IntVar(&rateLimit, "rateLimit", 5, "Specify the rate limit for API requests")

	return cmd
}

func newServeMailCMD() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mail",
		Short: "Serve DNS security queries via a dedicated email account",
		Run: func(_ *cobra.Command, _ []string) {
			sc, err := scanner.New(log, timeout, getScannerOpts()...)
			if err != nil {
				log.Fatal().Err(err).Msg("Could not create domain scanner")
			}

			mailServer, err := mail.NewMailServer(mailConfig, log, sc, advisor.NewAdvisor(timeout, cache, checkTLS))
			if err != nil {
				log.Fatal().Err(err).Msg("Could not open mail server connection")
			}

			mailServer.CheckTLS = checkTLS

			mailServer.Serve(interval)
		},
	}

	cmd.Flags().StringVar(&mailConfig.Inbound.Host, "inboundHost", "", "Incoming mail host and port")
	cmd.Flags().StringVar(&mailConfig.Inbound.Pass, "inboundPass", "", "Incoming mail password")
	cmd.Flags().StringVar(&mailConfig.Inbound.User, "inboundUser", "", "Incoming mail username")
	cmd.Flags().DurationVar(&interval, "interval", 30*time.Second, "Set the mail check interval in seconds")
	cmd.Flags().StringVar(&mailConfig.Outbound.Host, "outboundHost", "", "Outgoing mail host and port")
	cmd.Flags().StringVar(&mailConfig.Outbound.Pass, "outboundPass", "", "Outgoing mail password")
	cmd.Flags().StringVar(&mailConfig.Outbound.User, "outboundUser", "", "Outgoing mail username")

	if err := setRequiredFlags(cmd, "inboundHost", "inboundPass", "inboundUser", "outboundHost", "outboundPass", "outboundUser"); err != nil {
		log.Fatal().Err(err).Msg("Unable to set required flags for 'serve mail' command")
	}

	return cmd
}
