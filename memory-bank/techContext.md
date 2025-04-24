# Tech Context: gitpod-network-check

**Core Technologies:**

*   **Language:** Go (Golang)
*   **CLI Framework:** Cobra (`github.com/spf13/cobra`)
*   **Configuration Management:** Viper (`github.com/spf13/viper`)
*   **Logging:** Logrus (`github.com/sirupsen/logrus`)
*   **AWS Interaction (EC2 Mode):** AWS SDK for Go v2 (`github.com/aws/aws-sdk-go-v2`)
    *   Services used: EC2, IAM, SSM
*   **HTTP Requests (Local Mode):** Go Standard Library (`net/http`)

**Development Setup:**

*   Standard Go development environment (`go build`, `go test`, etc.).
*   Dependencies managed via Go Modules (`go.mod`, `go.sum`).
*   Likely developed within a containerized environment like Gitpod or Dev Containers for consistency.

**Technical Constraints:**

*   **EC2 Mode:** Requires valid AWS credentials with sufficient permissions to create/manage EC2 instances, IAM roles/profiles, and security groups, and to use SSM. Assumes network connectivity for the AWS SDK itself.
*   **Local Mode:** Relies on the network connectivity of the machine running the CLI. May not accurately reflect connectivity from within specific AWS subnets if run externally.
*   **Go Version:** Compatibility depends on the Go version specified in `go.mod`.

**Key Dependencies:**

*   `github.com/spf13/cobra`: CLI framework
*   `github.com/spf13/viper`: Configuration
*   `github.com/sirupsen/logrus`: Logging
*   `github.com/aws/aws-sdk-go-v2/*`: AWS SDK components
*   `golang.org/x/sync/errgroup`: Concurrency management
*   `k8s.io/apimachinery/pkg/util/wait`: Polling/waiting utilities (used in EC2 runner)
