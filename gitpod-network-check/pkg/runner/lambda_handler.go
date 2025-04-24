package runner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/gitpod-io/enterprise-deployment-toolkit/gitpod-network-check/pkg/lambda_types"
	log "github.com/sirupsen/logrus"
)

// HandleLambdaEvent is handling the Lambda event.
// This function is called by the aws-lambda-go library.
func HandleLambdaEvent(ctx context.Context, request lambda_types.CheckRequest) (lambda_types.CheckResponse, error) {
	log.Infof("Lambda Handler: Received check request for %d endpoints.", len(request.Endpoints))

	// Load AWS config once if not already loaded
	var signer *v4.Signer
	log.Info("Lambda Handler: Initializing AWS SDK config...")
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Errorf("Lambda Handler: Failed to load AWS config: %v", err)
		// Return an error that prevents further processing if config fails
		return lambda_types.CheckResponse{}, fmt.Errorf("failed to load AWS config: %w", err)
	}
	signer = v4.NewSigner()
	log.Infof("Lambda Handler: AWS SDK config loaded for region %s.", awsCfg.Region)

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

		signingErr := signAWSRequest(ctx, req, signer, &awsCfg)
		if signingErr != nil {
			response.Results[name] = lambda_types.CheckResult{Success: false, Error: fmt.Sprintf("failed to sign request: %v", signingErr)}
			log.Warnf("  -> Failed (signing): %v", signingErr)
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

func signAWSRequest(ctx context.Context, req *http.Request, signer *v4.Signer, awsCfg *aws.Config) error {
	targetUrl := req.URL

	isAwsEndpoint := strings.Contains(targetUrl.Host, ".amazonaws.com")
	if isAwsEndpoint {
		log.Debugf("Attempting SigV4 signing for AWS endpoint: %s", targetUrl.String())
		service, region, parseErr := parseAWSEndpoint(targetUrl.Host)
		if parseErr != nil {
			return fmt.Errorf("Failed to parse AWS service/region from %s: %v.", targetUrl.Host, parseErr)
		}

		// Retrieve credentials
		creds, credErr := awsCfg.Credentials.Retrieve(ctx)
		if credErr != nil {
			return fmt.Errorf("failed to retrieve AWS credentials: %v", credErr)
		}

		// Sign the request
		// For GET/HEAD requests with no body, use "UNSIGNED-PAYLOAD"
		log.Infof("Signing request '%s' for AWS service: %s, region: %s", targetUrl.String(), service, region)
		signErr := signer.SignHTTP(ctx, creds, req, "UNSIGNED-PAYLOAD", service, region, time.Now())
		if signErr != nil {
			return fmt.Errorf("Failed SigV4 signing: %v", signErr)
		}
	}

	return nil
}

// parseAWSEndpoint attempts to extract the service name and region from an AWS endpoint hostname.
func parseAWSEndpoint(hostname string) (service string, region string, err error) {
	if !strings.HasSuffix(hostname, ".amazonaws.com") {
		return "", "", fmt.Errorf("hostname does not end with .amazonaws.com")
	}

	// Trim the suffix
	trimmedHost := strings.TrimSpace(strings.TrimSuffix(hostname, ".amazonaws.com"))
	if trimmedHost == "" {
		return "", "", fmt.Errorf("invalid AWS hostname format: '%s' is missing the service/region part", hostname)
	}

	parts := strings.Split(trimmedHost, ".")
	if len(parts) < 1 {
		return "", "", fmt.Errorf("invalid AWS hostname format: %s", hostname)
	}

	// Handle ECR format: {account}.dkr.ecr.{region}
	if len(parts) >= 4 && parts[1] == "dkr" && parts[2] == "ecr" {
		service = "ecr"
		region = parts[3]
		return service, region, nil
	}

	// Handle api.ecr.{region}
	if len(parts) == 3 && parts[0] == "api" && parts[1] == "ecr" {
		service = "ecr"
		region = parts[2]
		return service, region, nil
	}

	// Handle execute-api format: {api-id}.execute-api.{region}
	if len(parts) >= 3 && parts[1] == "execute-api" {
		service = "execute-api"
		region = parts[2]
		return service, region, nil
	}

	// Handle standard {service}.{region} format
	if len(parts) >= 2 {
		service = parts[0]
		region = parts[1]
		// Basic validation for region format (e.g., xx-xxxx-d)
		if len(strings.Split(region, "-")) == 3 {
			return service, region, nil
		}
		// Fall through if region format doesn't match standard
	}

	// Handle global service format: {service} (e.g., s3, iam)
	if len(parts) == 1 {
		service = parts[0]
		// Default region for signing global services is often us-east-1
		// See: https://docs.aws.amazon.com/general/latest/gr/sigv4-service-endpoints.html
		region = "us-east-1"
		log.Debugf("Assuming global service '%s', using default signing region '%s'", service, region)
		return service, region, nil
	}

	// If we reached here, parsing failed based on known patterns
	return "", "", fmt.Errorf("could not determine service/region from hostname: %s", hostname)
}
