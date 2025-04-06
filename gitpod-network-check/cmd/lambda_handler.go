package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/gitpod-io/enterprise-deployment-toolkit/gitpod-network-check/pkg/lambda_types"
)

// Core logic for handling the Lambda event
// This function is called by the aws-lambda-go library.
func handleLambdaEvent(ctx context.Context, request lambda_types.CheckRequest) (lambda_types.CheckResponse, error) {
	log.Infof("Lambda Handler: Received check request for %d endpoints.", len(request.Endpoints))

	response := lambda_types.CheckResponse{
		Results: make(map[string]lambda_types.CheckResult),
	}

	client := &http.Client{
		Timeout: 10 * time.Second, // Consider making this configurable if needed
	}

	// Perform checks
	for name, url := range request.Endpoints {
		log.Debugf("Lambda Handler: Checking endpoint: %s (%s)", name, url)

		// Use the context provided by the Lambda runtime
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			response.Results[name] = lambda_types.CheckResult{Success: false, Error: fmt.Sprintf("failed to create request: %v", err)}
			log.Warnf("  -> Failed (request creation): %v", err)
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			response.Results[name] = lambda_types.CheckResult{Success: false, Error: fmt.Sprintf("HTTP request failed: %v", err)}
			log.Warnf("  -> Failed (HTTP request): %v", err)
		} else {
			resp.Body.Close() // Ensure body is closed
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				response.Results[name] = lambda_types.CheckResult{Success: true}
				log.Debugf("  -> Success (Status: %d)", resp.StatusCode)
			} else {
				response.Results[name] = lambda_types.CheckResult{Success: false, Error: fmt.Sprintf("unexpected status code: %d", resp.StatusCode)}
				log.Warnf("  -> Failed (Status: %d)", resp.StatusCode)
			}
		}
	}

	log.Info("Lambda Handler: Check processing complete.")
	// The lambda library handles marshalling the response and deals with errors.
	// We return the response struct and nil error if processing logic itself didn't fail critically.
	return response, nil
}

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
		lambda.Start(handleLambdaEvent)
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
