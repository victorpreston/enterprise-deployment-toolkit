package checks

import (
	"fmt"
	"net/url"
	"strings"

	log "github.com/sirupsen/logrus"
)

type NetworkConfig struct {
	LogLevel  string
	CfgFile   string
	AwsRegion string
	Destroy   bool
	Cleanup   bool

	MainSubnets []string
	PodSubnets  []string
	HttpsHosts  []string
	InstanceAMI string
	ApiEndpoint string

	// Lambda-specific configuration
	LambdaRoleArn         string
	LambdaSecurityGroupID string
}

func (nc *NetworkConfig) GetAllSubnets() []Subnet {
	var subnets []Subnet
	for _, subnet := range nc.MainSubnets {
		subnets = append(subnets, Subnet{SubnetID: subnet, Type: SubnetTypeMain})
	}
	for _, subnet := range nc.PodSubnets {
		subnets = append(subnets, Subnet{SubnetID: subnet, Type: SubnetTypePod})
	}
	return subnets
}

type TestsetName string

const (
	TestsetNameAwsServicesPodSubnet  TestsetName = "aws-services-pod-subnet"
	TestSetNameAwsServicesMainSubnet TestsetName = "aws-services-main-subnet"
	TestSetNameHttpsHostsMainSubnet  TestsetName = "https-hosts-main-subnet"
)

type SubnetType string

const (
	SubnetTypeMain SubnetType = "main"
	SubnetTypePod  SubnetType = "pod"
)

type Subnet struct {
	SubnetID string
	Type     SubnetType
}

func (s Subnet) String() string {
	return fmt.Sprintf("%s (%s)", s.SubnetID, s.Type)
}

func SubnetsFromIDs(subnets []string, typ SubnetType) []Subnet {
	var result []Subnet
	for _, subnetID := range subnets {
		result = append(result, Subnet{SubnetID: subnetID, Type: typ})
	}
	return result
}

type Subnets []Subnet

func (sns Subnets) String() string {
	var result []string
	for _, subnet := range sns {
		result = append(result, subnet.String())
	}
	return strings.Join(result, ", ")
}

type TestSet func(networkConfig *NetworkConfig) (endpoints map[string]string, subnetType SubnetType)

var TestSets = map[TestsetName]TestSet{
	TestsetNameAwsServicesPodSubnet: func(networkConfig *NetworkConfig) (map[string]string, SubnetType) {
		return map[string]string{
			"SSM":                   fmt.Sprintf("https://ssm.%s.amazonaws.com", networkConfig.AwsRegion),
			"SSMmessages":           fmt.Sprintf("https://ssmmessages.%s.amazonaws.com", networkConfig.AwsRegion),
			"Autoscaling":           fmt.Sprintf("https://autoscaling.%s.amazonaws.com", networkConfig.AwsRegion),
			"CloudFormation":        fmt.Sprintf("https://cloudformation.%s.amazonaws.com", networkConfig.AwsRegion),
			"EC2":                   fmt.Sprintf("https://ec2.%s.amazonaws.com", networkConfig.AwsRegion),
			"EC2messages":           fmt.Sprintf("https://ec2messages.%s.amazonaws.com", networkConfig.AwsRegion),
			"EKS":                   fmt.Sprintf("https://eks.%s.amazonaws.com", networkConfig.AwsRegion),
			"Elastic LoadBalancing": fmt.Sprintf("https://elasticloadbalancing.%s.amazonaws.com", networkConfig.AwsRegion),
			"Kinesis Firehose":      fmt.Sprintf("https://firehose.%s.amazonaws.com", networkConfig.AwsRegion),
			"KMS":                   fmt.Sprintf("https://kms.%s.amazonaws.com", networkConfig.AwsRegion),
			"CloudWatch":            fmt.Sprintf("https://logs.%s.amazonaws.com", networkConfig.AwsRegion),
			"SecretsManager":        fmt.Sprintf("https://secretsmanager.%s.amazonaws.com", networkConfig.AwsRegion),
			"Sts":                   fmt.Sprintf("https://sts.%s.amazonaws.com", networkConfig.AwsRegion),
			"ECR Api":               fmt.Sprintf("https://api.ecr.%s.amazonaws.com", networkConfig.AwsRegion),
			"ECR":                   fmt.Sprintf("https://869456089606.dkr.ecr.%s.amazonaws.com", networkConfig.AwsRegion),
		}, SubnetTypePod
	},
	TestSetNameAwsServicesMainSubnet: func(networkConfig *NetworkConfig) (map[string]string, SubnetType) {
		endpoints := map[string]string{
			"S3":       fmt.Sprintf("https://s3.%s.amazonaws.com", networkConfig.AwsRegion),
			"DynamoDB": fmt.Sprintf("https://dynamodb.%s.amazonaws.com", networkConfig.AwsRegion),
		}
		if networkConfig.ApiEndpoint != "" {
			endpoints["ExecuteAPI"] = fmt.Sprintf("https://%s.execute-api.%s.amazonaws.com", networkConfig.ApiEndpoint, networkConfig.AwsRegion)
		}
		return endpoints, SubnetTypeMain
	},
	TestSetNameHttpsHostsMainSubnet: func(networkConfig *NetworkConfig) (map[string]string, SubnetType) {
		endpoints := map[string]string{}
		for _, v := range networkConfig.HttpsHosts {
			host := strings.TrimSpace(v)
			parsedUrl, err := url.Parse(host)
			if err != nil {
				log.Warnf("🚧 Invalid Host: %s, skipping due to error: %v", host, err)
				continue
			}

			if parsedUrl.Scheme == "" {
				endpoints[host] = fmt.Sprintf("https://%s", host)
			} else if parsedUrl.Scheme == "https" {
				endpoints[host] = parsedUrl.Host
			} else {
				log.Warnf("🚧 Unsupported scheme: %s, skipping test for %s", parsedUrl.Scheme, host)
				continue
			}
		}
		return endpoints, SubnetTypeMain
	},
}
