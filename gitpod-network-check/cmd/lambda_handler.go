package cmd

import (
	"fmt"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/gitpod-io/enterprise-deployment-toolkit/gitpod-network-check/pkg/runner"
)

// lambdaHandlerCmd is the Cobra command invoked when the binary is run with the "lambda-handler" argument.
// This happens inside the AWS Lambda environment via the bootstrap script.
var lambdaHandlerCmd = &cobra.Command{
	Use:    "lambda-handler",
	Short:  "Internal command used by AWS Lambda runtime to execute network checks",
	Hidden: true, // Hide this command from user help output
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// override parent, as we don't care about the config or other flags when run by lambda
		// Ensure logs go to stderr (Lambda standard)
		log.SetOutput(os.Stderr)
		// Optionally set log level from env var if needed, e.g., os.Getenv("LOG_LEVEL")
		// Consider setting a default level appropriate for Lambda execution.
		log.SetLevel(log.InfoLevel) // Example: Set a default level
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		// The aws-lambda-go library takes over execution when lambda.Start is called.
		// It handles reading events, invoking the handler, and writing responses.
		log.Info("Lambda Handler: Starting AWS Lambda handler loop.")
		lambda.Start(runner.HandleLambdaEvent)
		// lambda.Start blocks and never returns unless there's a critical error during initialization
		log.Error("Lambda Handler: lambda.Start returned unexpectedly (should not happen)")
		return fmt.Errorf("lambda.Start returned unexpectedly")
	},
	// Disable flag parsing for this internal command as input comes from Lambda event payload
	DisableFlagParsing: true,
}

func init() {
	// Register the hidden lambda handler command
	// It's invoked by the Lambda runtime via the bootstrap script
	NetworkCheckCmd.AddCommand(lambdaHandlerCmd)
}
