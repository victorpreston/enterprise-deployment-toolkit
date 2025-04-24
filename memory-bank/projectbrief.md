# Project Brief: gitpod-network-check

**Core Purpose:**

`gitpod-network-check` is a command-line interface (CLI) tool designed to diagnose network connectivity issues relevant to deploying and running Gitpod Self-Hosted or Gitpod Dedicated instances.

**Key Goals:**

*   Provide a reliable way for administrators and support engineers to verify network prerequisites for Gitpod.
*   Test connectivity from relevant network segments (e.g., pod subnets, main subnets) to required external services (AWS APIs, container registries, etc.) and internal components.
*   Support different testing backends (e.g., EC2 instances, potentially Lambda, local execution) to suit various environments and testing needs.
*   Offer clear, actionable output indicating success or failure for specific checks.
*   Manage any temporary infrastructure created for testing (e.g., EC2 instances, security groups).
