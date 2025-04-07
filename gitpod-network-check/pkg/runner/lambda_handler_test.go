package runner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gitpod-io/enterprise-deployment-toolkit/gitpod-network-check/pkg/lambda_types"
	cmp "github.com/google/go-cmp/cmp" // Added for deep comparison
	log "github.com/sirupsen/logrus"
)

// TestHandleLambdaEvent tests the core logic within the Lambda handler function.
func TestHandleLambdaEvent(t *testing.T) {

	tests := []struct {
		name         string
		request      lambda_types.CheckRequest
		expectedResp lambda_types.CheckResponse
	}{
		{
			name: "successful http check",
			request: lambda_types.CheckRequest{
				Endpoints: map[string]string{
					"example_http": "http://example.com", // Use http to avoid cert issues in test
				},
			},
			expectedResp: lambda_types.CheckResponse{
				Results: map[string]lambda_types.CheckResult{
					"example_http": {Success: true},
				},
			},
		},
		{
			name: "successful https check",
			request: lambda_types.CheckRequest{
				Endpoints: map[string]string{
					"example_https": "https://example.com",
				},
			},
			expectedResp: lambda_types.CheckResponse{
				Results: map[string]lambda_types.CheckResult{
					"example_https": {Success: true},
				},
			},
		},
		{
			name: "failed http check - 404",
			// Assuming httpbin gives a 404 for this path
			request: lambda_types.CheckRequest{
				Endpoints: map[string]string{
					"httpbin_404": "http://httpbin.org/status/404",
				},
			},
			expectedResp: lambda_types.CheckResponse{
				Results: map[string]lambda_types.CheckResult{
					"httpbin_404": {Success: false, Error: "unexpected status code: 404"},
				},
			},
		},
		{
			name: "failed http check - connection refused",
			// Use a port likely not open on localhost
			request: lambda_types.CheckRequest{
				Endpoints: map[string]string{
					"localhost_conn_refused": "http://127.0.0.1:1",
				},
			},
			expectedResp: lambda_types.CheckResponse{
				Results: map[string]lambda_types.CheckResult{
					// Error message might vary slightly depending on OS/network stack - adjust if needed after running
					"localhost_conn_refused": {Success: false, Error: "HTTP request failed: Get \"http://127.0.0.1:1\": dial tcp 127.0.0.1:1: connect: connection refused"},
				},
			},
		},
		{
			name: "multiple endpoints - mix success and failure",
			request: lambda_types.CheckRequest{
				Endpoints: map[string]string{
					"example_ok":   "https://example.com",
					"httpbin_404":  "http://httpbin.org/status/404",
					"conn_refused": "http://127.0.0.1:1",
				},
			},
			expectedResp: lambda_types.CheckResponse{
				Results: map[string]lambda_types.CheckResult{
					"example_ok":  {Success: true},
					"httpbin_404": {Success: false, Error: "unexpected status code: 404"},
					// Error message might vary slightly depending on OS/network stack - adjust if needed after running
					"conn_refused": {Success: false, Error: "HTTP request failed: Get \"http://127.0.0.1:1\": dial tcp 127.0.0.1:1: connect: connection refused"},
				},
			},
		},
	}

	// Setup mock HTTP server for reliable testing of external URLs
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check the path to determine the response, as Host will be the mock server's address
		if r.URL.Path == "/status/404" {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintln(w, "Not Found")
		} else if r.URL.Path == "/" { // Assume requests to the root are for the "success" case
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "OK")
		} else {
			// Log unexpected paths to help debug test failures
			log.Warnf("Mock server received request for unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, "Mock server default - unexpected path")
		}
	}))
	defer mockServer.Close()

	// Replace external URLs in test cases with mock server URL
	// This makes tests faster and more reliable (no external network dependency)
	for i := range tests {
		newEndpoints := make(map[string]string)
		for name, url := range tests[i].request.Endpoints {
			switch url {
			case "http://example.com", "https://example.com":
				newEndpoints[name] = mockServer.URL
			case "http://httpbin.org/status/404":
				newEndpoints[name] = mockServer.URL + "/status/404"
			default:
				newEndpoints[name] = url // Keep internal/localhost URLs as is
			}
		}
		tests[i].request.Endpoints = newEndpoints
	}

	for _, tt := range tests {
		tt := tt // Capture range variable
		t.Run(tt.name, func(t *testing.T) {
			actualResp, err := HandleLambdaEvent(context.Background(), tt.request)
			if err != nil {
				t.Errorf("handleLambdaEvent returned an unexpected error: %v", err)
			}

			if diff := cmp.Diff(tt.expectedResp, actualResp); diff != "" {
				t.Errorf("handleLambdaEvent response mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
