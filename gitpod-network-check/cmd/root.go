package cmd

import (
	"fmt"
	"os"
	"path"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type NetworkConfig struct {
	LogLevel  string
	CfgFile   string
	AwsRegion string
	Destroy   bool
	Cleanup   bool

	MainSubnets []string
	PodSubnets  []string
}

var networkConfig = NetworkConfig{LogLevel: "INFO"}

var networkCheckCmd = &cobra.Command{ // nolint:gochecknoglobals
	PersistentPreRunE: configLogger,
	Use:               "gitpod-network-check",
	Short:             "CLI to check if your network is setup correctly to deploy Gitpod",
	SilenceUsage:      false,
}

func configLogger(cmd *cobra.Command, args []string) error {
	lvl, err := log.ParseLevel(networkConfig.LogLevel)
	if err != nil {
		log.WithField("log-level", networkConfig.CfgFile).Fatal("incorrect log level")

		return fmt.Errorf("incorrect log level")
	}

	log.SetLevel(lvl)
	log.WithField("log-level", networkConfig.CfgFile).Debug("log level configured")

	return nil
}

func bindFlags(cmd *cobra.Command, v *viper.Viper) {
	cmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		// Environment variables can't have dashes in them, so bind them to their equivalent
		// keys with underscores, e.g. --favorite-color to STING_FAVORITE_COLOR
		if strings.Contains(f.Name, "-") {
			envVarSuffix := strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))

			err := v.BindEnv(f.Name, fmt.Sprintf("%s_%s", "CDHT", envVarSuffix))
			if err != nil {
				log.Fatal(err)
				os.Exit(-1)
			}
		}

		// Apply the viper config value to the flag when the flag is not set and viper has a value
		if !f.Changed && v.IsSet(f.Name) {
			val := v.Get(f.Name)

			err := cmd.PersistentFlags().Set(f.Name, fmt.Sprintf("%v", val))
			if err != nil {
				log.Fatal(err)
				os.Exit(-1)
			}
		}
	})
}

func init() {
	v := readConfigFile()

	networkCheckCmd.PersistentFlags().StringVar(&networkConfig.CfgFile, "log-level",
		"info", "set log level verbosity (options: debug, info, error, warning)")

	networkCheckCmd.PersistentFlags().StringVar(&networkConfig.CfgFile, "config", "", "config file "+
		"(default is ./gitpod-network-check.yaml)")

	networkCheckCmd.PersistentFlags().StringVar(&networkConfig.AwsRegion, "region", "eu-central-1", "AWS Region to create the cell in")
	networkCheckCmd.PersistentFlags().StringSliceVar(&networkConfig.MainSubnets, "main-subnets", []string{}, "List of main subnets")
	networkCheckCmd.PersistentFlags().StringSliceVar(&networkConfig.PodSubnets, "pod-subnets", []string{}, "List of pod subnets")
	networkCheckCmd.PersistentFlags().BoolVarP(&networkConfig.Destroy, "rm", "r", false, "Setting this will cleanup the stack at the end of diagnosis")
	networkCheckCmd.PersistentFlags().BoolVarP(&networkConfig.Cleanup, "cleanup", "c", false, "Cleanup an existing stack")
	bindFlags(networkCheckCmd, v)
}

func readConfigFile() *viper.Viper {
	v := viper.New()
	if networkConfig.CfgFile != "" {
		// Use config file from the flag.
		v.SetConfigFile(networkConfig.CfgFile)
	} else {
		// Find current directory.
		currentDir := path.Dir("")

		// Search config in current directory with name (without extension).
		v.AddConfigPath(currentDir)
		v.SetConfigType("yaml")
		v.SetConfigName("gitpod-network-check")
	}

	// Attempt to read the config file, gracefully ignoring errors
	// caused by a config file not being found. Return an error
	// if we cannot parse the config file.
	if err := v.ReadInConfig(); err != nil {
		// It's okay if there isn't a config file
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			log.Info(err)
		}
	}

	v.SetEnvPrefix("NTCHK")

	// Bind to environment variables
	// Works great for simple config names, but needs help for names
	// like --favorite-color which we fix in the bindFlags function
	v.AutomaticEnv()

	return v
}

func Execute() error {
	networkCheckCmd.AddCommand(checkCommand)
	return networkCheckCmd.Execute()
}
