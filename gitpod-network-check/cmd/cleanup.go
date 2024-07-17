package cmd

import (
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/spf13/cobra"
)

var cleanCommand = &cobra.Command{ // nolint:gochecknoglobals
	PersistentPreRunE: validateSubnets,
	Use:               "clean",
	Short:             "Explicitly cleans up after the network check diagnosis",
	SilenceUsage:      false,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := initAwsConfig(cmd.Context(), networkConfig.AwsRegion)
		if err != nil {
			return err
		}

		ec2Client := ec2.NewFromConfig(cfg)
		iamClient := iam.NewFromConfig(cfg)

		cleanup(cmd.Context(), ec2Client, iamClient)
		return nil
	},
}
