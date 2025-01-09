package main

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/globalcyberalliance/domain-security-scanner/v3/pkg/model"
	"github.com/goccy/go-json"
	"github.com/rs/zerolog"
	"github.com/spf13/cast"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// support OS-specific path separators.
const slash = string(os.PathSeparator)

var (
	cmd = &cobra.Command{
		Use:     "dss",
		Short:   "Scan a domain's DNS records.",
		Long:    "Scan a domain's DNS records.\nhttps://github.com/globalcyberalliance/domain-security-scanner",
		Version: "3.0.14",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			var logWriter io.Writer

			if prettyLog {
				logWriter = zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
			} else {
				logWriter = os.Stdout
			}

			if debug {
				log = zerolog.New(logWriter).With().Timestamp().Logger().Level(zerolog.DebugLevel)
			} else {
				log = zerolog.New(logWriter).With().Timestamp().Logger().Level(zerolog.InfoLevel)
			}

			configDir, err := os.UserHomeDir()
			if err != nil {
				log.Fatal().Err(err).Msg("unable to retrieve user's home directory")
			}

			cfg, err = NewConfig(fmt.Sprintf("%s%s.config%sdomain-security-scanner", strings.TrimSuffix(configDir, slash), slash, slash))
			if err != nil {
				log.Fatal().Err(err).Msg("unable to initialize config")
			}

			if len(nameservers) == 0 {
				nameservers = cfg.Nameservers
			}

			if cmd.Flags().Changed("outputFile") {
				if outputFile == "" {
					outputFile = cast.ToString(time.Now().Unix())
				}
			}
		},
	}

	cfg                                          *Config
	log                                          zerolog.Logger
	writeToFileCounter                           int
	dnsProtocol, format, outputFile              string
	dkimSelector, nameservers                    []string
	advise, debug, checkTLS, prettyLog, zoneFile bool
	dnsBuffer                                    uint16
	cache, timeout                               time.Duration
	concurrent                                   uint16
)

func main() {
	cmd.PersistentFlags().BoolVarP(&advise, "advise", "a", false, "Provide suggestions for incorrect/missing mail security features")
	cmd.PersistentFlags().DurationVar(&cache, "cache", 3*time.Minute, "Specify how long to cache results for")
	cmd.PersistentFlags().BoolVar(&checkTLS, "checkTLS", false, "Check the TLS connectivity and cert validity of domains")
	cmd.PersistentFlags().Uint16VarP(&concurrent, "concurrent", "c", uint16(runtime.NumCPU()), "The number of domains to scan concurrently")
	cmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Print debug logs")
	cmd.PersistentFlags().StringSliceVar(&dkimSelector, "dkimSelector", []string{}, "Specify a DKIM selector")
	cmd.PersistentFlags().Uint16Var(&dnsBuffer, "dnsBuffer", 4096, "Specify the allocated buffer for DNS responses")
	cmd.PersistentFlags().StringVar(&dnsProtocol, "dnsProtocol", "udp", "Protocol to use for DNS queries (udp, tcp, tcp-tls)")
	cmd.PersistentFlags().StringVarP(&format, "format", "f", "yaml", "Format to print results in (yaml, json)")
	cmd.PersistentFlags().StringSliceVarP(&nameservers, "nameservers", "n", nil, "Use specific nameservers, in `host[:port]` format; may be specified multiple times")
	cmd.PersistentFlags().StringVarP(&outputFile, "outputFile", "o", "", "Output the results to a specified file (creates a file with the current unix timestamp if no file is specified)")
	cmd.PersistentFlags().BoolVar(&prettyLog, "prettyLog", true, "Pretty print logs to console")
	cmd.PersistentFlags().DurationVarP(&timeout, "timeout", "t", 15*time.Second, "Timeout duration for queries")
	cmd.PersistentFlags().BoolVarP(&zoneFile, "zoneFile", "z", false, "Input file/pipe containing an RFC 1035 zone file")

	_ = cmd.Execute()
}

func marshal(data interface{}) (output []byte) {
	switch strings.ToLower(format) {
	case "csv":
		// convert data to model.ScanResultWithAdvice
		scan, ok := data.(model.ScanResultWithAdvice)
		if !ok {
			log.Error().Msg("invalid data type")
			return nil
		}

		// write to csv in buffer
		var buffer bytes.Buffer
		writer := csv.NewWriter(&buffer)
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

func printToConsole(data interface{}) {
	if outputFile != "" {
		extension := format
		if extension == "jsonp" {
			extension = "json"
		}

		filename := outputFile + "." + extension
		if writeToFileCounter > 0 {
			filename = outputFile + "." + cast.ToString(writeToFileCounter) + "." + extension
		}

		printToFile(data, filename)
		log.Info().Msg("Output written to " + filename)
		writeToFileCounter++
		return
	}

	fmt.Print(string(marshal(data)))
}

func printToFile(data interface{}, file string) {
	outputPrintFile, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE, os.ModePerm)
	if err != nil {
		return
	}
	defer outputPrintFile.Close()

	if _, err = outputPrintFile.Write(marshal(data)); err != nil {
		log.Fatal().Err(err).Msg("failed to write output to file")
	}
}

func setRequiredFlags(command *cobra.Command, flags ...string) error {
	for _, flag := range flags {
		if err := command.MarkFlagRequired(flag); err != nil {
			return err
		}
	}

	return nil
}
