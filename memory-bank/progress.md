# Progress: gitpod-network-check (2025-04-03)

**What Works:**

*   Core CLI structure (`diagnose`, `cleanup` commands).
*   Configuration loading (Viper).
*   Logging (Logrus).
*   `ec2` mode:
    *   Creates necessary AWS resources (IAM Role/Profile, Security Group, EC2 Instance per subnet).
    *   Uses SSM to run connectivity checks (`curl`) from within the EC2 instances.
    *   Cleans up created AWS resources.
*   Definition of `TestSets` for AWS services and generic HTTPS hosts.

**What's Left to Build:**

*   **Local Mode Implementation:**
    *   `pkg/runner/local-runner.go` file creation.
    *   `LocalTestRunner` struct and `NewLocalTestRunner` constructor.
    *   Implementation of `Prepare`, `TestService` (using `net/http`), and `Cleanup` methods for `LocalTestRunner`.
*   **Integration of Local Mode:**
    *   Update `cmd/checks.go` to recognize and instantiate `LocalTestRunner`.
    *   Update `cmd/root.go` flag help text for `--mode`.
*   **Lambda Mode:** (Future/Potential) Implementation is stubbed or incomplete in `cmd/checks.go`. Requires a `LambdaTestRunner`.
*   **Testing:** Add unit/integration tests for the new `local` mode.

**Current Status:**

*   Actively working on implementing the `local` execution mode.
*   Memory Bank has been initialized.

**Known Issues/Challenges:**

*   `ec2` mode requires significant AWS permissions and can take time due to resource provisioning/cleanup.
*   `local` mode tests connectivity *from* the machine running the CLI, which might not perfectly represent connectivity *from* the Gitpod cluster nodes/pods within their specific subnets. This limitation should be documented or made clear to the user.
