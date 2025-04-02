package cmd

import (
	"fmt"
	"maps"
	"slices"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/gitpod-io/enterprise-deployment-toolkit/gitpod-network-check/pkg/checks"
	testrunner "github.com/gitpod-io/enterprise-deployment-toolkit/gitpod-network-check/pkg/runner"
)

type Mode string

const (
	ModeEC2    Mode = "ec2"
	ModeLambda Mode = "lambda"
)

var validModes = map[string]bool{
	string(ModeLambda): true,
	string(ModeEC2):    true,
}

var flags = struct {
	// Variable to store the testsets flag value
	SelectedTestsets []string

	// Variable to store the mode flag value
	ModeVar string

	Mode Mode
}{}

var checkCommand = &cobra.Command{ // nolint:gochecknoglobals
	PersistentPreRunE: validateArguments,
	Use:               "diagnose",
	Short:             "Runs the network check diagnosis",
	SilenceUsage:      false,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		var runner testrunner.TestRunner
		if flags.Mode == ModeEC2 {
			ec2Runner, err := testrunner.NewEC2TestRunner(ctx, &networkConfig)
			if err != nil {
				return fmt.Errorf("❌  failed to create EC2 test runner: %v", err)
			}
			runner = ec2Runner
		}
		defer (func() {
			log.Infof("ℹ️  Running cleanup")
			terr := runner.Cleanup(ctx)
			if terr != nil {
				log.Errorf("❌ failed to cleanup: %v", terr)
			}
			log.Infof("✅  Cleanup done")
		})()

		// Prepare
		err := runner.Prepare(ctx)
		if err != nil {
			return fmt.Errorf("❌  failed to prepare: %v", err)
		}

		for _, testset := range flags.SelectedTestsets {
			log.Infof("ℹ️  Running testset: %s", testset)

			ts := checks.TestSets[checks.TestsetName(testset)]
			serviceEndpoints, subnetType := ts(&networkConfig)
			subnets := Filter(networkConfig.GetAllSubnets(), func(subnet checks.Subnet) bool {
				return subnet.Type == subnetType
			})

			testResult, err := runner.TestService(ctx, subnets, serviceEndpoints)
			if err != nil {
				log.Errorf("❌  failed to run testset %s: %v", testset, err)
				break
			}

			if !testResult {
				log.Errorf("❌  Testset %s failed", testset)
			} else {
				log.Infof("✅  Testset %s passed", testset)
			}
		}

		return nil
	},
}

func validateArguments(cmd *cobra.Command, args []string) error {
	// Validate mode
	if !validModes[flags.ModeVar] {
		return fmt.Errorf("invalid mode: %s, must be one of: %v", flags.ModeVar, maps.Keys(validModes))
	}
	flags.Mode = Mode(flags.ModeVar)

	// Validate testsets if specified
	if len(flags.SelectedTestsets) > 0 {
		for _, testset := range flags.SelectedTestsets {
			if _, exists := checks.TestSets[checks.TestsetName(testset)]; !exists {
				return fmt.Errorf("Invalid testset: %s. Available testsets: %v",
					testset,
					slices.Collect(maps.Keys(checks.TestSets)))
			}
		}
	} else {
		log.Info("ℹ️  No testsets specified, running no testsets")
	}

	return nil
}

func Filter[T comparable](slice []T, f func(T) bool) []T {
	var result []T
	for _, v := range slice {
		if f(v) {
			result = append(result, v)
		}
	}
	return result
}
