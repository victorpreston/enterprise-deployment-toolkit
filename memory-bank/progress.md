# Progress: gitpod-network-check (2025-04-03)

**What Works:**

*   Core CLI structure using Cobra.
*   Configuration loading via Viper (flags, file).
*   `diagnose` command framework.
*   `TestRunner` interface defined.
*   `ec2` mode:
    *   Launches EC2 instances in specified subnets.
    *   Uses SSM to run check scripts on instances.
    *   Performs basic connectivity checks.
    *   `cleanup` command removes EC2 resources.
*   `local` mode:
    *   Runs checks directly from the CLI host using Go's `net/http`.
*   `lambda` mode:
    *   `LambdaTestRunner` implemented (`Prepare`, `TestService`, `Cleanup`).
    *   Internal `lambda-handler` subcommand created (`cmd/lambda_handler.go`) to perform checks inside Lambda, using shared types (`pkg/lambda_types`).
    *   `Prepare` handles IAM role, SG creation, packaging the *main binary* with a `bootstrap` script, and Lambda deployment per subnet using `provided.al2` runtime.
    *   `TestService` invokes Lambdas per subnet and aggregates JSON results.
    *   `Prepare` handles IAM role, SG creation (or uses existing ones via flags/config), packaging the main binary with a `bootstrap` script, Lambda deployment per subnet using `provided.al2` runtime, and waits for functions to become active. Includes basic deferred cleanup on error.
    *   `TestService` invokes Lambdas per subnet and aggregates JSON results.
    *   `Cleanup` handles Lambda function, CloudWatch Log Group deletion, and deletes managed SG/IAM role (skips deletion if user-provided).
    *   Integrated into `diagnose` (via `runner.NewRunner`) and `cleanup` commands.
    *   Flags (`--lambda-role-arn`, `--lambda-sg-id`) and config options added.
    *   Help text updated.
    *   README documentation updated for Lambda mode prerequisites and usage.
    *   Aligned resource tagging (`gitpod.io/network-check: true`) with EC2 mode.
    *   Removed ad-hoc cleanup logic from `Prepare`.
    *   Added `LoadLambdaRunnerFromTags` to discover existing resources for cleanup.
    *   Integrated `LoadLambdaRunnerFromTags` into the `cleanup` command via `LoadRunnerFromTags`.
    *   Removed separate Lambda handler code (`lambda/checker/`) and cleaned dependencies.

**What's Left to Build:**

*   **`lambda` mode enhancements:**
    *   Testing in a real AWS environment.
    *   Consider more sophisticated rollback logic in `Prepare` if needed beyond basic deferred cleanup.

**Current Status:**

*   Implementation of `lambda` mode enhancements (Log Group cleanup, readiness wait, existing resource flags, documentation, aligned tagging) and cleanup refactoring completed.
*   Ready for testing.

**Known Issues:**

*   Error handling during resource creation in `Prepare` relies solely on the caller invoking `Cleanup`. Complex partial failures might leave orphaned resources if `Cleanup` is not called or fails itself.
