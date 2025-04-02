package runner

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"

	"github.com/gitpod-io/enterprise-deployment-toolkit/gitpod-network-check/pkg/checks"
)

type TestRunner interface {
	Prepare(ctx context.Context) error
	TestService(ctx context.Context, subnets []checks.Subnet, serviceEndpoints map[string]string) (bool, error)
	Cleanup(ctx context.Context) error
}

func initAwsConfig(ctx context.Context, region string) (aws.Config, error) {
	return config.LoadDefaultConfig(ctx, config.WithRegion(region))
}
