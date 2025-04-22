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

// NetworkConfig holds the application configuration, populated from flags/config file
var NetworkConfig = checks.NetworkConfig{LogLevel: "INFO"}

// Flags holds parsed flag values
var Flags = struct {
	// Variable to store the testsets flag value
	SelectedTestsets []string

	// Variable to store the runner flag value
	RunnerTypeStr string

	RunnerType runner.RunnerType
}{}

// NetworkCheckCmd is the root command for the application
var NetworkCheckCmd = &cobra.Command{ // nolint:gochecknoglobals
	PersistentPreRunE: preRunE,
	Use:               "gitpod-network-check",
	Short:             "CLI to check if your network is setup correctly to deploy Gitpod",
	SilenceUsage:      false,
}

func preRunE(cmd *cobra.Command, args []string) error {
	// setup logger
	lvl, err := log.ParseLevel(NetworkConfig.LogLevel)
	if err != nil {
		return fmt.Errorf("❌  incorrect log level: %v", err)
	}

	log.SetLevel(lvl)
	log.WithField("log-level", NetworkConfig.CfgFile).Debug("log level configured")

	// Log the effective configuration after setup and binding (Moved from init)
	log.Infof("ℹ️  Running with region `%s`, main subnet `%v`, pod subnet `%v`, hosts `%v`, ami `%v`, and API endpoint `%v`", NetworkConfig.AwsRegion, NetworkConfig.MainSubnets, NetworkConfig.PodSubnets, NetworkConfig.HttpsHosts, NetworkConfig.InstanceAMI, NetworkConfig.ApiEndpoint)

	// validate the config
	err = validateSubnetsConfig(cmd, args)
	if err != nil {
		return fmt.Errorf("❌  incorrect subnets: %v", err)
	}

	err = validateRunnerFlag(cmd, args)
	if err != nil {
		return fmt.Errorf("❌  incorrect runner: %v", err) // Update error message context
	}

	return nil
}

func validateSubnetsConfig(cmd *cobra.Command, args []string) error {
	if len(NetworkConfig.MainSubnets) < 1 {
		return fmt.Errorf("At least one Main subnet needs to be specified: %v", NetworkConfig.MainSubnets)
	}
	log.Info("✅ Main Subnets are valid")
	if len(NetworkConfig.PodSubnets) < 1 {
		return fmt.Errorf("At least one Pod subnet needs to be specified: %v", NetworkConfig.PodSubnets)
	}
	log.Info("✅ Pod Subnets are valid")

	return nil
}

func validateRunnerFlag(cmd *cobra.Command, args []string) error {
	// Validate runnerType
	runnerType, err := runner.ValidateRunnerType(Flags.RunnerTypeStr)
	if err != nil {
		return err
	}
	Flags.RunnerType = runnerType

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

	NetworkCheckCmd.PersistentFlags().StringVar(&NetworkConfig.LogLevel, "log-level",
		"info", "set log level verbosity (options: debug, info, error, warning)")

	NetworkCheckCmd.PersistentFlags().StringVar(&NetworkConfig.CfgFile, "config", "", "config file "+
		"(default is ./gitpod-network-check.yaml)")

	NetworkCheckCmd.PersistentFlags().StringVar(&NetworkConfig.AwsRegion, "region", "eu-central-1", "AWS Region to create the cell in")
	NetworkCheckCmd.PersistentFlags().StringSliceVar(&NetworkConfig.MainSubnets, "main-subnets", []string{}, "List of main subnets")
	NetworkCheckCmd.PersistentFlags().StringSliceVar(&NetworkConfig.PodSubnets, "pod-subnets", []string{}, "List of pod subnets")
	NetworkCheckCmd.PersistentFlags().StringSliceVar(&NetworkConfig.HttpsHosts, "https-hosts", []string{}, "Hosts to test for outbound HTTPS connectivity")
	NetworkCheckCmd.PersistentFlags().StringVar(&NetworkConfig.InstanceAMI, "instance-ami", "", "Custom ec2 instance AMI id, if not set will use latest ubuntu")
	NetworkCheckCmd.PersistentFlags().StringVar(&NetworkConfig.ApiEndpoint, "api-endpoint", "", "The Gitpod Enterprise control plane's regional API endpoint subdomain")
	testsetOptions := []string{string(checks.TestsetNameAwsServicesApp), string(checks.TestSetNameAwsServicesSubstrate), string(checks.TestSetNameHttpsHosts)}
	NetworkCheckCmd.PersistentFlags().StringSliceVar(&Flags.SelectedTestsets, "testsets", testsetOptions, fmt.Sprintf("List of testsets to run (options: %v)", testsetOptions))
	// Rename flag, variable, and update help text
	NetworkCheckCmd.PersistentFlags().StringVar(&Flags.RunnerTypeStr, "runner", string(runner.RunnerTypeEC2), fmt.Sprintf("Specify the runner for executing tests (default: %s, options: %s, %s, %s)", runner.RunnerTypeEC2, runner.RunnerTypeEC2, runner.RunnerTypeLambda, runner.RunnerTypeLocal))
	// Lambda-specific flags
	NetworkCheckCmd.PersistentFlags().StringVar(&NetworkConfig.LambdaRoleArn, "lambda-role-arn", "", "ARN of an existing IAM role to use for Lambda execution (overrides automatic creation/deletion)")
	NetworkCheckCmd.PersistentFlags().StringVar(&NetworkConfig.LambdaSecurityGroupID, "lambda-sg-id", "", "ID of an existing Security Group to use for Lambda execution (overrides automatic creation/deletion)")

	bindFlags(NetworkCheckCmd, v)
}

func readConfigFile() *viper.Viper {
	v := viper.New()
	if NetworkConfig.CfgFile != "" {
		// Use config file from the flag.
		v.SetConfigFile(NetworkConfig.CfgFile)
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

// Execute runs the root command
func Execute() error {
	return NetworkCheckCmd.Execute()
}
