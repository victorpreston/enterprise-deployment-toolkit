package runner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/gitpod-io/enterprise-deployment-toolkit/gitpod-network-check/pkg/checks"
)

// LocalTestRunner executes network checks directly from the local machine.
type LocalTestRunner struct {
	// No fields needed for local runner currently
}

// NewLocalTestRunner creates a new instance of LocalTestRunner.
func NewLocalTestRunner() *LocalTestRunner {
	log.Info("ℹ️  Using local test runner")
	return &LocalTestRunner{}
}

// Prepare performs any setup required for the local runner. Currently a no-op.
func (r *LocalTestRunner) Prepare(ctx context.Context) error {
	log.Debug("Local runner Prepare: No preparation needed.")
	return nil // No setup needed for local execution
}

// TestService runs connectivity tests to the specified service endpoints from the local machine.
// The subnets parameter is ignored in local mode.
func (r *LocalTestRunner) TestService(ctx context.Context, subnets []checks.Subnet, serviceEndpoints map[string]string) (bool, error) {
	log.Debugf("Local runner TestService: Ignoring subnets (%d provided)", len(subnets))
	overallSuccess := true

	httpClient := &http.Client{
		Timeout: 15 * time.Second, // Sensible default timeout
		Transport: &http.Transport{
			// Consider adding proxy support if needed later
			// Proxy: http.ProxyFromEnvironment,
			DisableKeepAlives: true, // Avoid reusing connections for distinct tests
		},
	}

	for name, endpointURL := range serviceEndpoints {
		log.Infof("ℹ️  Testing connectivity to %s (%s) locally...", name, endpointURL)

		// Ensure URL includes scheme
		parsedURL, err := url.Parse(endpointURL)
		if err != nil {
			log.Errorf("❌ Failed to parse URL for %s (%s): %v", name, endpointURL, err)
			overallSuccess = false
			continue
		}
		if parsedURL.Scheme == "" {
			// Default to HTTPS if no scheme is provided
			parsedURL.Scheme = "https"
			endpointURL = parsedURL.String()
			log.Debugf("Assuming HTTPS for %s: %s", name, endpointURL)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodHead, endpointURL, nil)
		if err != nil {
			log.Errorf("❌ Failed to create request for %s (%s): %v", name, endpointURL, err)
			overallSuccess = false
			continue
		}

		// Add a user-agent?
		// req.Header.Set("User-Agent", "gitpod-network-check/local")

		resp, err := httpClient.Do(req)
		if err != nil {
			log.Errorf("❌ Failed to connect to %s (%s): %v", name, endpointURL, err)
			overallSuccess = false
			continue
		}
		resp.Body.Close() // Ensure body is closed even if not read

		// Consider any 2xx or 3xx status code as success for a HEAD request.
		// Some services might return 403 Forbidden for HEAD but are still reachable.
		// Let's be lenient for now and accept anything < 500.
		if resp.StatusCode >= 500 {
			log.Errorf("❌ Connection test failed for %s (%s): Received status code %d", name, endpointURL, resp.StatusCode)
			overallSuccess = false
		} else {
			log.Infof("✅ Successfully connected to %s (%s) - Status: %d", name, endpointURL, resp.StatusCode)
		}
	}

	if !overallSuccess {
		return false, fmt.Errorf("one or more local connectivity tests failed")
	}

	log.Info("✅ All local connectivity tests passed.")
	return true, nil
}

// Cleanup performs any teardown required for the local runner. Currently a no-op.
func (r *LocalTestRunner) Cleanup(ctx context.Context) error {
	log.Debug("Local runner Cleanup: No cleanup needed.")
	return nil // No cleanup needed for local execution
}
