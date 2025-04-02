package cmd

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/gitpod-io/enterprise-deployment-toolkit/gitpod-network-check/pkg/runner"
)

var cleanCommand = &cobra.Command{ // nolint:gochecknoglobals
	PersistentPreRunE: validateSubnets,
	Use:               "clean",
	Short:             "Explicitly cleans up after the network check diagnosis",
	SilenceUsage:      false,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		log.Infof("ℹ️ Running cleanup")
		runner, err := runner.LoadEC2RunnerFromTags(ctx, &networkConfig)
		if err != nil {
			log.WithError(err).Fatal("Failed to load EC2 runner")
		}

		err = runner.Cleanup(ctx)
		if err != nil {
			return fmt.Errorf("❌ failed to cleanup: %v", err)
		}
		log.Infof("✅ Cleanup done")

		return nil
	},
}
