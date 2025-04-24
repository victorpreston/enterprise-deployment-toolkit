# PDD-001: Lambda Runner AWS Endpoint Authentication

**Status:** Proposed

**Author:** Cline

**Date:** 2025-04-22

## 1. Problem Statement

The `gitpod-network-check` tool, when executed with the `--runner=lambda` option, fails to check connectivity to several AWS service endpoints (e.g., ECR, KMS, SSM, EKS, ELB). The failures manifest as HTTP 4xx errors (401 Unauthorized, 403 Forbidden, 400 Bad Request, 404 Not Found) in the logs.

```
time="2025-04-22T07:49:50Z" level=warning msg=" -> Failed (Status: 401)" endpoint="https://869456089606.dkr.ecr.eu-central-1.amazonaws.com"
time="2025-04-22T07:49:50Z" level=warning msg=" -> Failed (Status: 400)" endpoint="https://elasticloadbalancing.eu-central-1.amazonaws.com"
time="2025-04-22T07:49:50Z" level=warning msg=" -> Failed (Status: 404)" endpoint="https://kms.eu-central-1.amazonaws.com"
# ... and others
```

Conversely, running the checks with `--runner=ec2` against the same endpoints succeeds. This indicates an issue specific to the Lambda execution environment or its implementation, rather than fundamental network connectivity problems (like security groups or NACLs blocking traffic).

## 2. Analysis & Root Cause

Initial investigation focused on the implementation differences between the EC2 and Lambda runners.

*   **`pkg/runner/lambda_handler.go`:** The code executed *inside* the Lambda function performs checks using Go's standard `net/http` client to make simple `GET` requests to the target endpoint URLs. It does **not** use the AWS SDK or perform any AWS-specific authentication (like SigV4 signing).
*   **`pkg/runner/ec2-runner.go`:** Surprisingly, the EC2 runner *also* uses simple, unauthenticated HTTP requests (`curl -I <url>` executed via SSM Run Command).

This finding invalidated the initial hypothesis that the EC2 runner used authenticated SDK calls while the Lambda runner did not.

The revised root cause analysis points to the difference in how AWS service endpoints treat unauthenticated requests originating from different environments:

1.  **Lambda Environment:** Requests from the Lambda environment (even within a VPC) to AWS service APIs generally require strict AWS Signature Version 4 (SigV4) authentication. Simple, unauthenticated HTTP requests are rejected with 4xx errors because they lack the necessary `Authorization` header.
2.  **EC2 Environment (via SSM):** While the `curl` command itself is unauthenticated, the context in which it runs might influence endpoint behavior. The EC2 instance has an associated IAM role (via Instance Profile). AWS endpoints might be less strict or have different internal routing/authentication checks for requests originating from an EC2 instance within the VPC, potentially allowing a simple `HEAD` request (`curl -I`) to succeed where a `GET` from Lambda fails. The exact mechanism isn't fully clear but the observed behavior difference is consistent.

**Conclusion:** The Lambda runner fails because its unauthenticated HTTP requests do not meet the authentication requirements of the target AWS service API endpoints when originating from the Lambda execution environment.

## 3. Goal

Modify the Lambda runner implementation to ensure that checks against AWS service endpoints requiring authentication can succeed by leveraging the permissions granted to the Lambda function's execution role.

## 4. Proposed Solution: SigV4 Signed HTTP Requests

To address the authentication requirement while retaining the user's preference for dynamic URL checking, the proposed solution is to modify the Lambda handler to sign its outgoing HTTP requests using AWS Signature Version 4 (SigV4).

**Implementation Steps:**

1.  **Modify Lambda Handler (`pkg/runner/lambda_handler.go`):**
    *   Load the default AWS SDK configuration (`config.LoadDefaultConfig(ctx)`) within the `HandleLambdaEvent` function. This allows access to the Lambda execution role's credentials and the region.
    *   For each target endpoint URL:
        *   Parse the URL to extract the target AWS service name (e.g., "ecr", "kms") and region. This information is essential for the SigV4 signing process. Standard AWS endpoint formats (`service.region.amazonaws.com`) should be handled.
        *   Create a standard `http.Request` object (e.g., using `http.NewRequestWithContext`). A `HEAD` request is generally preferable for a simple connectivity/authentication check, falling back to `GET` if `HEAD` is not supported by an endpoint.
        *   Retrieve the AWS credentials from the loaded SDK configuration (`cfg.Credentials.Retrieve(ctx)`).
        *   Utilize an AWS SDK SigV4 signing utility (e.g., potentially needing to implement a helper using `v4.Signer` or similar low-level SDK components) to sign the `http.Request`. The signer needs the credentials, service name, region, and the request object. It will add the necessary `Authorization` and other SigV4 headers.
        *   Execute the *signed* request using a standard `http.Client`.
        *   Evaluate the response: An HTTP status code in the 2xx range generally indicates success. Some endpoints might return 404 for a `HEAD` or `GET` to the root, which could still be considered a successful authentication check. Status codes 401/403 clearly indicate failure due to permissions. The exact success criteria per service might need refinement.

2.  **Add Required IAM Permissions (`pkg/runner/lambda-runner.go`):**
    *   The Lambda execution role (`GitpodNetworkCheckLambdaRole` or user-provided) will need IAM permissions corresponding to the actions implicitly performed by accessing the target endpoints, even with just a `HEAD` or `GET`.
    *   In the `getOrCreateLambdaRole` function (if *not* using a user-provided `lambdaRoleArn`):
        *   Define an inline IAM policy granting necessary read-only actions. Examples include:
            *   `ecr:GetAuthorizationToken`
            *   `kms:ListKeys`
            *   `ssm:DescribeParameters`
            *   `secretsmanager:ListSecrets`
            *   `logs:DescribeLogGroups`
            *   `eks:ListClusters`
            *   `elasticloadbalancing:DescribeLoadBalancers`
            *   `ec2:DescribeRegions` (or more specific actions if needed for `ec2messages`/`ssmmessages` validation)
            *   `execute-api:Invoke` (if checking API Gateway endpoints)
        *   Attach this policy to the role using `iamClient.PutRolePolicy`.

3.  **Update Go Modules (`go.mod`, `go.sum`):**
    *   Add required AWS SDK v2 modules, including `config`, `credentials`, and any specific signing utility packages. Run `go mod tidy`.

## 5. Alternatives Considered

1.  **Service-Specific SDK Calls:**
    *   *Description:* Instead of signing generic HTTP requests, use high-level SDK clients (e.g., `ecr.NewFromConfig`, `kms.NewFromConfig`) and call specific API actions (e.g., `DescribeRepositories`, `ListKeys`).
    *   *Pros:* Simpler SDK usage, potentially more explicit checks.
    *   *Cons:* Less flexible; requires mapping endpoint URLs to specific SDK calls, making it harder to support arbitrary AWS endpoints provided in the config. Rejected because the user preferred maintaining the dynamic URL checking approach.

2.  **User-Provided Pre-configured IAM Role:**
    *   *Description:* Require the user to create an IAM role with all necessary permissions (Lambda execution, VPC access, service endpoint access) and provide its ARN via the `lambdaRoleArn` config key. The tool would skip role creation and use the provided one.
    *   *Pros:* Shifts IAM management entirely to the user, requires no permission logic changes in the tool.
    *   *Cons:* Requires manual setup by the user. Less "automatic" than the tool managing its own resources. This remains a viable alternative if the proposed solution proves too complex.

## 6. Success Criteria

*   The `gitpod-network-check --runner=lambda` command successfully checks connectivity to AWS service endpoints that previously failed with 4xx errors.
*   The checks utilize the Lambda execution role's credentials via SigV4 signing.
*   The tool continues to function correctly for non-AWS endpoints or endpoints not requiring SigV4.
*   The automatically created IAM role (if used) includes the necessary permissions for the checks performed.
*   Cleanup procedures correctly remove any created resources (including inline policies if the managed role is used).

## 7. Open Questions/Risks

*   **Endpoint Parsing:** Reliably parsing service name and region from arbitrary AWS endpoint URLs might be complex (e.g., handling private endpoints, FIPS endpoints, non-standard formats).
*   **IAM Permissions:** Determining the *minimal* required IAM actions for a successful `HEAD`/`GET` check against each service endpoint might require experimentation. Overly broad permissions (`*`) should be avoided if possible.
*   **SigV4 Implementation:** Correctly implementing the SigV4 signing for standard `http.Request` might require careful use of SDK internals or specific signing packages.
*   **Success Definition:** Defining what HTTP status code constitutes a "successful" check for each type of endpoint needs care (e.g., is 404 okay for a `HEAD` request to a service root?).
