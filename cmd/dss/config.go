package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cast"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func newConfigCMD() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Configure your DSS instance",
	}

	cmd.AddCommand(newConfigGetCMD())
	cmd.AddCommand(newConfigSetCMD())
	cmd.AddCommand(newConfigShowCMD())

	return cmd
}

func newConfigGetCMD() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "get",
		Short:   "Get a config value",
		Example: "  dss config get nameservers",
		Args:    cobra.ExactArgs(1),
		Run: func(_ *cobra.Command, args []string) {
			switch args[0] {
			case "nameservers":
				printToConsole("nameservers: " + cast.ToString(cfg.Nameservers))
			default:
				log.Fatal().Msg("Unknown config key")
			}
		},
	}

	return cmd
}

func newConfigSetCMD() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "set",
		Short:   "Set a config value",
		Example: "  dss config set nameservers 8.8.8.8,9.9.9.9",
		Args:    cobra.ExactArgs(2),
		Run: func(_ *cobra.Command, args []string) {
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

	return cmd
}

func newConfigShowCMD() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "show",
		Short:   "Print full config",
		Example: "  dss config show",
		Args:    cobra.ExactArgs(0),
		Run: func(_ *cobra.Command, _ []string) {
			printToConsole(cfg)
		},
	}

	return cmd
}

type Config struct {
	dir         string
	path        string
	Nameservers []string `json:"nameservers" yaml:"nameservers"`
}

func newConfig(directory string) (*Config, error) {
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
	// Create config if it doesn't exist.
	if _, err := os.Stat(c.path); os.IsNotExist(err) {
		if err = os.MkdirAll(c.dir, 0o750); err != nil {
			log.Fatal().Err(err).Msg("Failed to create config directory")
		}

		if err = c.Save(); err != nil {
			return err
		}
	}

	// Read config.
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

	if err = os.WriteFile(c.path, configData, os.ModePerm); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	return nil
}
