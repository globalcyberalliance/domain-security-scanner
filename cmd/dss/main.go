package main

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/globalcyberalliance/domain-security-scanner/v3/pkg/model"
	"github.com/globalcyberalliance/domain-security-scanner/v3/pkg/scanner"
	"github.com/goccy/go-json"
	"github.com/rs/zerolog"
	"github.com/spf13/cast"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// Support OS-specific path separators.
const slash = string(os.PathSeparator)
const version = "3.0.21"

var (
	advise, checkTLS, zoneFile bool
	cache, timeout             time.Duration
	concurrent                 uint16
	cfg                        *Config
	debug, prettyLog           bool
	dkimSelector, nameservers  []string
	dnsProtocol, outputFile    string
	dnsBuffer                  uint16
	format, logLevel           string
	log                        = zerolog.Logger{}
)

func main() {
	rootCMD := newRootCMD()
	rootCMD.AddCommand(newConfigCMD())
	rootCMD.AddCommand(newScanCMD())
	rootCMD.AddCommand(newServeCMD())

	if err := rootCMD.Execute(); err != nil {
		panic(err)
	}
}

func newRootCMD() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "dss",
		Short:   "Scan a domain's DNS records.",
		Long:    "Scan a domain's DNS records.\nhttps://github.com/globalcyberalliance/domain-security-scanner",
		Version: version,
		PersistentPreRun: func(_ *cobra.Command, _ []string) {
			configDir, err := os.UserHomeDir()
			if err != nil {
				log.Fatal().Err(err).Msg("unable to retrieve user's home directory")
			}

			cfg, err = newConfig(fmt.Sprintf("%s%s.config%sdomain-security-scanner", strings.TrimSuffix(configDir, slash), slash, slash))
			if err != nil {
				log.Fatal().Err(err).Msg("unable to initialize config")
			}

			logLevelParsed, err := zerolog.ParseLevel(strings.ToLower(logLevel))
			if err != nil {
				fmt.Printf("Unable to parse log level: %s: %v\n", logLevel, err)
				os.Exit(1)
			}

			if debug {
				logLevelParsed = zerolog.DebugLevel

				// Start pprof in the background.
				go func() {
					log.Info().Msg("Starting pprof on port 6060")

					const idleTimeout = 30 * time.Second
					const readTimeout = 10 * time.Second
					const writeTimeout = 10 * time.Second

					srv := &http.Server{Addr: ":6060", IdleTimeout: idleTimeout, ReadTimeout: readTimeout, WriteTimeout: writeTimeout}

					if err := srv.ListenAndServe(); err != nil {
						log.Error().Err(err).Msg("Pprof server failed")
					}
				}()
			}

			newLogger(logLevelParsed)

			log.Debug().Msg("CPU cores: " + cast.ToString(runtime.NumCPU()))
			log.Info().Str("version", version).Msg("Starting server")
		},
	}

	cmd.PersistentFlags().BoolVarP(&advise, "advise", "a", false, "Provide suggestions for incorrect/missing mail security features")
	cmd.PersistentFlags().DurationVar(&cache, "cache", 3*time.Minute, "Specify how long to cache results for")
	cmd.PersistentFlags().BoolVar(&checkTLS, "checkTLS", false, "Check the TLS connectivity and cert validity of domains")
	cmd.PersistentFlags().Uint16VarP(&concurrent, "concurrent", "c", uint16(runtime.NumCPU()), "The number of domains to scan concurrently")
	cmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Force log level to debug, and enable pprof for profiling")
	cmd.PersistentFlags().StringSliceVar(&dkimSelector, "dkimSelector", []string{}, "Specify a DKIM selector")
	cmd.PersistentFlags().Uint16Var(&dnsBuffer, "dnsBuffer", 4096, "Specify the allocated buffer for DNS responses")
	cmd.PersistentFlags().StringVar(&dnsProtocol, "dnsProtocol", "udp", "Protocol to use for DNS queries (udp, tcp, tcp-tls)")
	cmd.PersistentFlags().StringVarP(&format, "format", "f", "yaml", "Set the output format for CLI commands")
	cmd.PersistentFlags().StringVar(&logLevel, "logLevel", "info", "Set log level (debug, info, warn, error, fatal, panic)")
	cmd.PersistentFlags().StringSliceVarP(&nameservers, "nameservers", "n", nil, "Use specific nameservers, in `host[:port]` format; may be specified multiple times")
	cmd.PersistentFlags().StringVarP(&outputFile, "outputFile", "o", "", "Output the results to a specified file (creates a file with the current unix timestamp if no file is specified)")
	cmd.PersistentFlags().BoolVar(&prettyLog, "prettyLog", true, "Pretty print logs to console")
	cmd.PersistentFlags().DurationVarP(&timeout, "timeout", "t", 15*time.Second, "Timeout duration for queries")
	cmd.PersistentFlags().BoolVarP(&zoneFile, "zoneFile", "z", false, "Input file/pipe containing an RFC 1035 zone file")

	return cmd
}

func getScannerOpts() []scanner.Option {
	opts := []scanner.Option{
		scanner.WithCacheDuration(cache),
		scanner.WithConcurrentScans(concurrent),
		scanner.WithDNSBuffer(dnsBuffer),
		scanner.WithDNSProtocol(dnsProtocol),
		scanner.WithNameservers(nameservers),
	}

	if len(dkimSelector) > 0 {
		opts = append(opts, scanner.WithDKIMSelectors(dkimSelector...))
	}

	return opts
}

func marshal(data any, includeHeader bool) []byte {
	var output []byte

	switch strings.ToLower(format) {
	case "csv":
		// Check if the data is a slice of model.ScanResultWithAdvice.
		if scans, ok := data.([]model.ScanResultWithAdvice); ok {
			var buffer bytes.Buffer
			writer := csv.NewWriter(&buffer)

			if includeHeader {
				if err := writer.Write([]string{"domain", "BIMI", "DKIM", "DMARC", "MX", "SPF", "error", "advice"}); err != nil {
					log.Fatal().Err(err).Msg("Unable to write CSV header")
				}
			}

			for _, scan := range scans {
				if err := writer.Write(scan.CSV()); err != nil {
					log.Fatal().Err(err).Str("domain", scan.ScanResult.Domain).Msg("Unable to write CSV")
				}
			}

			writer.Flush()
			output = buffer.Bytes()

			return output
		}

		// Convert data to model.ScanResultWithAdvice.
		scan, ok := data.(model.ScanResultWithAdvice)
		if !ok {
			log.Error().Msg("Invalid data type")
			return nil
		}

		// Write to the csv in the buffer.
		var buffer bytes.Buffer
		writer := csv.NewWriter(&buffer)

		if includeHeader {
			if err := writer.Write([]string{"domain", "BIMI", "DKIM", "DMARC", "MX", "SPF", "error", "advice"}); err != nil {
				log.Fatal().Err(err).Msg("Unable to write CSV header")
			}
		}

		_ = writer.Write(scan.CSV())
		writer.Flush()
		output = buffer.Bytes()
	case "json":
		output, _ = json.Marshal(data)
	case "jsonp":
		output, _ = json.MarshalIndent(data, "", "\t")
	default:
		output, _ = yaml.Marshal(data)
	}

	return output
}

func newLogger(logLevel zerolog.Level) {
	var logWriter io.Writer

	if prettyLog {
		logWriter = zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	} else {
		logWriter = os.Stdout
	}

	log = zerolog.New(logWriter).With().Timestamp().Logger().Level(logLevel)
}

func printToConsole(data any) {
	if outputFile != "" {
		extension := format
		if extension == "jsonp" {
			extension = "json"
		}

		filename := outputFile
		if !strings.HasSuffix(strings.ToLower(outputFile), "."+strings.ToLower(extension)) {
			filename += "." + extension
		}

		if err := printToFile(data, filename); err != nil {
			log.Fatal().Err(err).Msg("Unable to write output file")
		}

		return
	}

	fmt.Print(string(marshal(data, true)))
}

func printToFile(data any, file string) error {
	includeHeader := false
	if info, err := os.Stat(file); os.IsNotExist(err) || (err == nil && info.Size() == 0) {
		includeHeader = true
	}

	outputPrintFile, err := os.OpenFile(file, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("open output file: %w", err)
	}
	defer outputPrintFile.Close()

	if _, err = outputPrintFile.Write(marshal(data, includeHeader)); err != nil {
		return fmt.Errorf("write output file: %w", err)
	}

	return nil
}

func setRequiredFlags(command *cobra.Command, flags ...string) error {
	for _, flag := range flags {
		if err := command.MarkFlagRequired(flag); err != nil {
			return fmt.Errorf("marking required flag %q: %w", flag, err)
		}
	}

	return nil
}
