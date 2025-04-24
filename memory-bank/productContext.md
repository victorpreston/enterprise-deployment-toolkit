# Product Context: gitpod-network-check

**Problem Solved:**

Deploying Gitpod requires specific network configurations to allow communication between its components and various external services (AWS APIs, container registries, identity providers, etc.). Misconfigurations are common and can be difficult to diagnose, leading to deployment failures or runtime issues. This tool aims to proactively identify these network connectivity problems before or during Gitpod installation/updates.

**How it Should Work:**

The tool executes predefined sets of network connectivity tests (`TestSets`) targeting specific endpoints required by Gitpod. These tests are run from environments that simulate where Gitpod components would run (e.g., within specific AWS subnets).

*   **Modes:** The tool supports different execution modes:
    *   `ec2`: (Existing) Launches temporary EC2 instances in specified subnets to run tests. Requires AWS credentials and permissions.
    *   `lambda`: (Planned/Partially Implemented?) Uses AWS Lambda functions for testing.
    *   `local`: (Current Task) Runs tests directly from the machine executing the CLI using standard Go libraries. Useful for basic outbound checks or when AWS resources aren't desired/available.
*   **Test Sets:** Groups of related checks (e.g., connectivity to core AWS services from pod subnets).
*   **Configuration:** Network details (subnets, region) and test parameters (hosts) are provided via CLI flags or a configuration file.
*   **Output:** Logs detailed information about each check, clearly indicating success or failure.
*   **Cleanup:** Automatically removes any temporary resources created during the `ec2` mode run.

**User Experience Goals:**

*   **Simplicity:** Easy to run with sensible defaults.
*   **Clarity:** Provide clear pass/fail results and informative error messages.
*   **Flexibility:** Allow users to select specific test sets and execution modes.
*   **Reliability:** Accurately reflect the network connectivity status relevant to Gitpod.
