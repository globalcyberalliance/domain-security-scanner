package main

import (
	"os"
	"strings"

	"github.com/spf13/cast"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func init() {
	cmd.AddCommand(cmdConfig)
	cmdConfig.AddCommand(cmdConfigGet)
	cmdConfig.AddCommand(cmdConfigSet)
	cmdConfig.AddCommand(cmdConfigShow)
}

var (
	cmdConfig = &cobra.Command{
		Use:   "config",
		Short: "Configure your DSS instance",
	}

	cmdConfigGet = &cobra.Command{
		Use:     "get",
		Short:   "Get a config value",
		Example: "  dss config get nameservers",
		Args:    cobra.ExactArgs(1),
		Run: func(command *cobra.Command, args []string) {
			switch args[0] {
			case "nameservers":
				printToConsole("nameservers: " + cast.ToString(cfg.Nameservers))
			default:
				log.Fatal().Msg("Unknown config key")
			}
		},
	}

	cmdConfigSet = &cobra.Command{
		Use:     "set",
		Short:   "Set a config value",
		Example: "  dss config set nameservers 8.8.8.8,9.9.9.9",
		Args:    cobra.ExactArgs(2),
		Run: func(command *cobra.Command, args []string) {
			switch args[0] {
			case "nameservers":
				cfg.Nameservers = strings.Split(args[1], ",")
			default:
				log.Fatal().Msg("Unknown config key")
			}

			if err := cfg.Save(); err != nil {
				log.Fatal().Err(err).Msg("Unable to save config")
			}

			log.Info().Msg("Config updated")
		},
	}

	cmdConfigShow = &cobra.Command{
		Use:     "show",
		Short:   "Print full config",
		Example: "  dss config show",
		Args:    cobra.ExactArgs(0),
		Run: func(command *cobra.Command, args []string) {
			printToConsole(cfg)
		},
	}
)

type Config struct {
	dir         string
	path        string
	Nameservers []string `json:"nameservers" yaml:"nameservers"`
}

func NewConfig(directory string) (*Config, error) {
	config := Config{
		dir:         directory,
		path:        directory + slash + "config.yml",
		Nameservers: []string{"8.8.8.8:53"},
	}

	if err := config.Load(); err != nil {
		return nil, err
	}

	return &config, nil
}

func (c *Config) Load() error {
	// create config if it doesn't exist
	if _, err := os.Stat(c.path); os.IsNotExist(err) {
		if err = os.MkdirAll(c.dir, os.ModePerm); err != nil {
			log.Fatal().Err(err).Msg("Failed to create config directory")
		}

		if err = c.Save(); err != nil {
			return err
		}
	}

	// read config
	configData, err := os.ReadFile(c.path)
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to read config file")
	}

	if err = yaml.Unmarshal(configData, &c); err != nil {
		log.Fatal().Err(err).Msg("Unable to unmarshal config values")
	}

	return nil
}

func (c *Config) Save() error {
	configData, err := yaml.Marshal(c)
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to marshal default config")
	}

	return os.WriteFile(c.path, configData, os.ModePerm)
}
