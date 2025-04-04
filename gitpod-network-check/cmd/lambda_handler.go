package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/gitpod-io/enterprise-deployment-toolkit/gitpod-network-check/pkg/lambda_types"
)

var lambdaHandlerCmd = &cobra.Command{
	Use:    "lambda-handler",
	Short:  "Internal command to execute network checks within AWS Lambda (reads JSON request from stdin, writes JSON response to stdout)",
	Hidden: true, // Hide this command from user help output
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// override parent, as we don't care about the config or other flags
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		// Lambda environment might not have sophisticated logging setup, print directly
		fmt.Fprintln(os.Stderr, "Lambda Handler: Starting execution.")

		// Read request payload from stdin
		stdinBytes, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Lambda Handler: Error reading stdin: %v\n", err)
			return fmt.Errorf("error reading stdin: %w", err)
		}

		var request lambda_types.CheckRequest
		err = json.Unmarshal(stdinBytes, &request)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Lambda Handler: Error unmarshalling request JSON: %v\n", err)
			fmt.Fprintf(os.Stderr, "Lambda Handler: Received input: %s\n", string(stdinBytes))
			return fmt.Errorf("error unmarshalling request: %w", err)
		}

		fmt.Fprintf(os.Stderr, "Lambda Handler: Received check request for %d endpoints.\n", len(request.Endpoints))

		response := lambda_types.CheckResponse{
			Results: make(map[string]lambda_types.CheckResult),
		}

		client := &http.Client{
			Timeout: 10 * time.Second, // Slightly longer timeout for Lambda environment?
		}

		// Perform checks (similar logic to the previous dedicated handler)
		for name, url := range request.Endpoints {
			fmt.Fprintf(os.Stderr, "Lambda Handler: Checking endpoint: %s (%s)\n", name, url)
			// Use context from command if needed, otherwise background context is fine here
			req, err := http.NewRequestWithContext(cmd.Context(), "GET", url, nil)
			if err != nil {
				response.Results[name] = lambda_types.CheckResult{Success: false, Error: fmt.Sprintf("failed to create request: %v", err)}
				fmt.Fprintf(os.Stderr, "  -> Failed (request creation): %v\n", err)
				continue
			}

			resp, err := client.Do(req)
			if err != nil {
				response.Results[name] = lambda_types.CheckResult{Success: false, Error: fmt.Sprintf("HTTP request failed: %v", err)}
				fmt.Fprintf(os.Stderr, "  -> Failed (HTTP request): %v\n", err)
			} else {
				resp.Body.Close() // Ensure body is closed
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					response.Results[name] = lambda_types.CheckResult{Success: true}
					fmt.Fprintf(os.Stderr, "  -> Success (Status: %d)\n", resp.StatusCode)
				} else {
					response.Results[name] = lambda_types.CheckResult{Success: false, Error: fmt.Sprintf("unexpected status code: %d", resp.StatusCode)}
					fmt.Fprintf(os.Stderr, "  -> Failed (Status: %d)\n", resp.StatusCode)
				}
			}
		}

		// Marshal response payload to stdout
		responseBytes, err := json.Marshal(response)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Lambda Handler: Error marshalling response JSON: %v\n", err)
			return fmt.Errorf("error marshalling response: %w", err)
		}

		_, err = fmt.Fprint(os.Stdout, string(responseBytes))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Lambda Handler: Error writing response to stdout: %v\n", err)
			return fmt.Errorf("error writing response: %w", err)
		}

		fmt.Fprintln(os.Stderr, "Lambda Handler: Execution complete.")
		return nil
	},
	// Disable flag parsing for this internal command as it gets input via stdin
	DisableFlagParsing: true,
}

func init() {
	// Note: We don't add this to networkCheckCmd directly in init() here
	// because it might interfere with normal flag parsing if not careful.
	// It will be added in the main Execute() function or similar central place.
	// For now, just define the command struct.
	// We also need to ensure logging doesn't interfere with stdout JSON output.
	// Maybe configure logging to stderr specifically for this command?
	lambdaHandlerCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		// Ensure logs go to stderr for this command to keep stdout clean for JSON
		log.SetOutput(os.Stderr)
	}

	NetworkCheckCmd.AddCommand(lambdaHandlerCmd) // Register the hidden lambda handler command
}
