# System Patterns: gitpod-network-check

**Core Architecture:**

*   **CLI Application:** Built using Go and the Cobra library for command structure and flag parsing.
*   **Configuration:** Uses Viper for managing configuration from files (e.g., `gitpod-network-check.yaml`) and environment variables, layered with CLI flags.
*   **Modular Test Execution:** Employs a `TestRunner` interface (`pkg/runner/common.go`) to abstract the environment where network tests are executed. This allows plugging in different backends (EC2, Local, potentially Lambda).
*   **Test Definitions:** Test logic is grouped into `TestSets` (`pkg/checks/`), which are functions returning endpoints and subnet types to test.

**Key Patterns:**

*   **Strategy Pattern:** The `TestRunner` interface and its implementations (`EC2TestRunner`, `LocalTestRunner`) exemplify the Strategy pattern, allowing the test execution strategy to be selected at runtime (`--mode` flag).
*   **Dependency Injection (Implicit):** The `NetworkConfig` struct is populated from configuration sources and passed down to components that need it (like the `EC2TestRunner`).
*   **Resource Management (EC2):** The `EC2TestRunner` handles the lifecycle (Prepare, Cleanup) of temporary AWS resources (Instances, Roles, Security Groups) needed for testing. The `LocalTestRunner` requires no external resource management.
*   **Command Pattern (Cobra):** Cobra organizes CLI functionality into distinct `Command` objects (`diagnose`, `cleanup`).

**Component Relationships:**

```mermaid
graph TD
    CLI[gitpod-network-check CLI] --> RootCmd[cmd/root.go];
    RootCmd -- loads config --> Config[NetworkConfig];
    RootCmd -- registers --> DiagnoseCmd[cmd/checks.go];
    RootCmd -- registers --> CleanupCmd[cmd/cleanup.go];

    DiagnoseCmd -- uses --> Config;
    DiagnoseCmd -- selects based on mode --> RunnerInterface[pkg/runner/common.go#TestRunner];
    RunnerInterface -- implemented by --> EC2Runner[pkg/runner/ec2-runner.go];
    RunnerInterface -- implemented by --> LocalRunner[pkg/runner/local-runner.go];

    DiagnoseCmd -- uses --> TestSets[pkg/checks/];
    TestSets -- define --> Endpoints;
    TestSets -- define --> SubnetTypes;

    EC2Runner -- uses --> AWS_SDK[AWS SDK (EC2, IAM, SSM)];
    EC2Runner -- manages --> AWSResources[EC2 Instances, SG, IAM Roles];
    LocalRunner -- uses --> GoStdLib[Go net/http];

    CleanupCmd -- uses --> Config;
    CleanupCmd -- loads --> EC2Runner;
    EC2Runner -- Cleanup --> AWS_SDK;

    CLI -- entrypoint --> main.go;
    main.go -- calls --> RootCmd.Execute;

    style EC2Runner fill:#f9f,stroke:#333,stroke-width:2px;
    style LocalRunner fill:#ccf,stroke:#333,stroke-width:2px;
