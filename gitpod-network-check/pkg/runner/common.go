package runner

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"

	"github.com/gitpod-io/enterprise-deployment-toolkit/gitpod-network-check/pkg/checks"
)

type Mode string

const (
	ModeEC2    Mode = "ec2"
	ModeLambda Mode = "lambda"
	ModeLocal  Mode = "local"
)

var validModes = map[string]bool{
	string(ModeLambda): true,
	string(ModeEC2):    true,
	string(ModeLocal):  true,
}

func VaildateMode(modeStr string) (Mode, error) {
	if _, ok := validModes[modeStr]; ok {
		return Mode(modeStr), nil
	}
	return "", fmt.Errorf("invalid mode: %s, must be one of: %v", modeStr, slices.Collect(maps.Keys(validModes)))
}

type TestRunner interface {
	Prepare(ctx context.Context) error
	TestService(ctx context.Context, subnets []checks.Subnet, serviceEndpoints map[string]string) (bool, error)
	Cleanup(ctx context.Context) error
}

func NewRunner(ctx context.Context, mode Mode, config *checks.NetworkConfig) (TestRunner, error) {
	switch mode {
	case ModeEC2:
		return NewEC2TestRunner(context.Background(), config)
	case ModeLocal:
		return NewLocalTestRunner(), nil
	default:
		return nil, fmt.Errorf("invalid mode: %s, must be one of: %v", mode, slices.Collect(maps.Keys(validModes)))
	}
	// TODO: Add logic for ModeLambda if/when implemented
}

func initAwsConfig(ctx context.Context, region string) (aws.Config, error) {
	return config.LoadDefaultConfig(ctx, config.WithRegion(region))
}
