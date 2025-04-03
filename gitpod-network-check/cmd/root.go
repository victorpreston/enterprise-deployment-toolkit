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

	"github.com/gitpod-io/enterprise-deployment-toolkit/gitpod-network-check/pkg/checks"
	"github.com/gitpod-io/enterprise-deployment-toolkit/gitpod-network-check/pkg/runner"
)

var networkConfig = checks.NetworkConfig{LogLevel: "INFO"}

var flags = struct {
	// Variable to store the testsets flag value
	SelectedTestsets []string

	// Variable to store the mode flag value
	ModeVar string

	Mode runner.Mode
}{}

var networkCheckCmd = &cobra.Command{ // nolint:gochecknoglobals
	PersistentPreRunE: preRunE,
	Use:               "gitpod-network-check",
	Short:             "CLI to check if your network is setup correctly to deploy Gitpod",
	SilenceUsage:      false,
}

func preRunE(cmd *cobra.Command, args []string) error {
	// setup logger
	lvl, err := log.ParseLevel(networkConfig.LogLevel)
	if err != nil {
		return fmt.Errorf("❌  incorrect log level: %v", err)
	}

	log.SetLevel(lvl)
	log.WithField("log-level", networkConfig.CfgFile).Debug("log level configured")

	// validate the config
	err = validateSubnets(cmd, args)
	if err != nil {
		return fmt.Errorf("❌  incorrect subnets: %v", err)
	}

	err = validateMode(cmd, args)
	if err != nil {
		return fmt.Errorf("❌  incorrect mode: %v", err)
	}

	return nil
}

func validateSubnets(cmd *cobra.Command, args []string) error {
	if len(networkConfig.MainSubnets) < 1 {
		return fmt.Errorf("At least one Main subnet needs to be specified: %v", networkConfig.MainSubnets)
	}
	log.Info("✅ Main Subnets are valid")
	if len(networkConfig.PodSubnets) < 1 {
		return fmt.Errorf("At least one Pod subnet needs to be specified: %v", networkConfig.PodSubnets)
	}
	log.Info("✅ Pod Subnets are valid")

	return nil
}

func validateMode(cmd *cobra.Command, args []string) error {
	// Validate mode
	mode, err := runner.VaildateMode(flags.ModeVar)
	if err != nil {
		return err
	}
	flags.Mode = mode

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
	networkCheckCmd.PersistentFlags().StringSliceVar(&networkConfig.HttpsHosts, "https-hosts", []string{}, "Hosts to test for outbound HTTPS connectivity")
	networkCheckCmd.PersistentFlags().StringVar(&networkConfig.InstanceAMI, "instance-ami", "", "Custom ec2 instance AMI id, if not set will use latest ubuntu")
	networkCheckCmd.PersistentFlags().StringVar(&networkConfig.ApiEndpoint, "api-endpoint", "", "The Gitpod Enterprise control plane's regional API endpoint subdomain")
	networkCheckCmd.PersistentFlags().StringSliceVar(&flags.SelectedTestsets, "testsets", []string{"aws-services-pod-subnet", "aws-services-main-subnet", "https-hosts-main-subnet"}, "List of testsets to run (options: aws-services-pod-subnet, aws-services-main-subnet, https-hosts-main-subnet)")
	networkCheckCmd.PersistentFlags().StringVar(&flags.ModeVar, "mode", string(runner.ModeEC2), "How to run the tests (default: ec2, options: ec2, lambda, local)")
	bindFlags(networkCheckCmd, v)
	log.Infof("ℹ️  Running with region `%s`, main subnet `%v`, pod subnet `%v`, hosts `%v`, ami `%v`, and API endpoint `%v`", networkConfig.AwsRegion, networkConfig.MainSubnets, networkConfig.PodSubnets, networkConfig.HttpsHosts, networkConfig.InstanceAMI, networkConfig.ApiEndpoint)
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
	networkCheckCmd.AddCommand(cleanCommand)
	return networkCheckCmd.Execute()
}
