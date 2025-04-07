package runner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gitpod-io/enterprise-deployment-toolkit/gitpod-network-check/pkg/lambda_types"
	log "github.com/sirupsen/logrus"
)

// HandleLambdaEvent is handling the Lambda event.
// This function is called by the aws-lambda-go library.
func HandleLambdaEvent(ctx context.Context, request lambda_types.CheckRequest) (lambda_types.CheckResponse, error) {
	log.Infof("Lambda Handler: Received check request for %d endpoints.", len(request.Endpoints))

	response := lambda_types.CheckResponse{
		Results: make(map[string]lambda_types.CheckResult),
	}

	client := &http.Client{
		Timeout: 10 * time.Second, // Consider making this configurable if needed
	}

	// Perform checks
	for name, targetUrlStr := range request.Endpoints {

		targetUrl, err := url.Parse(targetUrlStr)
		if err != nil {
			response.Results[name] = lambda_types.CheckResult{Success: false, Error: fmt.Sprintf("invalid URL: %v", err)}
			log.Warnf("  -> Failed URL parsing for '%s': %v", targetUrlStr, err)
			continue
		}
		if targetUrl.Scheme == "" {
			// Default to HTTPS if no scheme is provided
			targetUrl.Scheme = "https"
		}

		log.Debugf("Lambda Handler: Checking endpoint: %s (%s)", name, targetUrl.String())

		// Use the context provided by the Lambda runtime
		log := log.WithField("endpoint", targetUrl.String())

		req, err := http.NewRequestWithContext(ctx, "GET", targetUrl.String(), nil)
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
