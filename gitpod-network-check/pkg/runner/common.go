package runner

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	ec2_types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	iam_types "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/gitpod-io/enterprise-deployment-toolkit/gitpod-network-check/pkg/checks"
)

type RunnerType string

const (
	RunnerTypeEC2    RunnerType = "ec2"
	RunnerTypeLambda RunnerType = "lambda"
	RunnerTypeLocal  RunnerType = "local"
)

var validRunnerType = map[string]bool{
	string(RunnerTypeLambda): true,
	string(RunnerTypeEC2):    true,
	string(RunnerTypeLocal):  true,
}

func ValidateRunnerType(runnerStr string) (RunnerType, error) {
	if _, ok := validRunnerType[runnerStr]; ok {
		return RunnerType(runnerStr), nil
	}
	return "", fmt.Errorf("invalid runner: %s, must be one of: %v", runnerStr, slices.Collect(maps.Keys(validRunnerType)))
}

type TestRunner interface {
	Prepare(ctx context.Context) error
	TestService(ctx context.Context, subnets []checks.Subnet, serviceEndpoints map[string]string) (bool, error)
	Cleanup(ctx context.Context) error
}

func NewRunner(ctx context.Context, mode RunnerType, config *checks.NetworkConfig) (TestRunner, error) {
	switch mode {
	case RunnerTypeEC2:
		return NewEC2TestRunner(context.Background(), config)
	case RunnerTypeLocal:
		return NewLocalTestRunner(), nil
	case RunnerTypeLambda:
		return NewLambdaTestRunner(ctx, config)
	default:
		// Update error message
		return nil, fmt.Errorf("invalid runner: %s, must be one of: %v", mode, slices.Collect(maps.Keys(validRunnerType)))
	}
}

// Creates a new TestRunner instance, loading existing resources from the AWS account by known name/tags.
// This is useful for cleaning up left-over resources from previous runs.
func LoadRunnerFromTags(ctx context.Context, mode RunnerType, networkConfig *checks.NetworkConfig) (TestRunner, error) {
	switch mode {
	case RunnerTypeEC2:
		return LoadEC2RunnerFromTags(ctx, networkConfig)
	case RunnerTypeLambda:
		return LoadLambdaRunnerFromTags(ctx, networkConfig) // Call the new function
	case RunnerTypeLocal:
		// Local mode does not require any AWS resources, so we can just return a new instance.
		return NewLocalTestRunner(), nil
	default:
		// Update error message
		return nil, fmt.Errorf("invalid runner: %s, must be one of: %v", mode, slices.Collect(maps.Keys(validRunnerType)))
	}
}

// AWS stuff
func initAwsConfig(ctx context.Context, region string) (aws.Config, error) {
	return config.LoadDefaultConfig(ctx, config.WithRegion(region))
}

const (
	// NetworkCheckTagKey is the tag key used to identify network check resources
	// in AWS.
	NetworkCheckTagKey = "gitpod.io/network-check"
	// NetworkCheckTagValue is the tag value used to identify network check resources
	// in AWS.
	NetworkCheckTagValue = "true"
)

var NetworkCheckTags = map[string]string{
	NetworkCheckTagKey: NetworkCheckTagValue,
}

var NetworkCheckIamTags = []iam_types.Tag{
	{
		Key:   aws.String(NetworkCheckTagKey),
		Value: aws.String(NetworkCheckTagValue),
	},
}

var NetworkCheckEC2Tags = []ec2_types.Tag{
	{
		Key:   aws.String(NetworkCheckTagKey),
		Value: aws.String(NetworkCheckTagValue),
	},
}

var NetworkCheckTagsFilter = []ec2_types.Filter{
	{
		Name:   aws.String(fmt.Sprintf("tag:%s", NetworkCheckTagKey)),
		Values: []string{NetworkCheckTagValue},
	},
}
