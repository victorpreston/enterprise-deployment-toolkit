package lambda_types

// CheckRequest defines the input structure for the Lambda function.
type CheckRequest struct {
	Endpoints map[string]string `json:"endpoints"` // Map of service name -> URL
}

// CheckResult defines the result for a single endpoint check.
type CheckResult struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// CheckResponse defines the output structure for the Lambda function.
type CheckResponse struct {
	Results map[string]CheckResult `json:"results"` // Map of service name -> CheckResult
}
