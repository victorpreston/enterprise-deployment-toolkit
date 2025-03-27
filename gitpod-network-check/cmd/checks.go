package cmd

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iam_types "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/smithy-go"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/util/wait"
)

type TestsetName string

const (
	TestsetNameAwsServicesPodSubnet  TestsetName = "aws-services-pod-subnet"
	TestSetNameAwsServicesMainSubnet TestsetName = "aws-services-main-subnet"
	TestSetNameHttpsHostsMainSubnet  TestsetName = "https-hosts-main-subnet"
)

type TestSet func(networkConfig *NetworkConfig) map[string]string

var testSets = map[TestsetName]TestSet{
	TestsetNameAwsServicesPodSubnet: func(networkConfig *NetworkConfig) map[string]string {
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
		}
	},
	TestSetNameAwsServicesMainSubnet: func(networkConfig *NetworkConfig) map[string]string {
		endpoints := map[string]string{
			"S3":       fmt.Sprintf("https://s3.%s.amazonaws.com", networkConfig.AwsRegion),
			"DynamoDB": fmt.Sprintf("https://dynamodb.%s.amazonaws.com", networkConfig.AwsRegion),
		}
		if networkConfig.ApiEndpoint != "" {
			endpoints["ExecuteAPI"] = fmt.Sprintf("https://%s.execute-api.%s.amazonaws.com", networkConfig.ApiEndpoint, networkConfig.AwsRegion)
		}
		return endpoints
	},
	TestSetNameHttpsHostsMainSubnet: func(networkConfig *NetworkConfig) map[string]string {
		httpHosts := map[string]string{}
		for _, v := range networkConfig.HttpsHosts {
			host := strings.TrimSpace(v)
			parsedUrl, err := url.Parse(host)
			if err != nil {
				log.Warnf("🚧 Invalid Host: %s, skipping due to error: %v", host, err)
				continue
			}

			if parsedUrl.Scheme == "" {
				httpHosts[host] = fmt.Sprintf("https://%s", host)
			} else if parsedUrl.Scheme == "https" {
				httpHosts[host] = parsedUrl.Host
			} else {
				log.Warnf("🚧 Unsupported scheme: %s, skipping test for %s", parsedUrl.Scheme, host)
				continue
			}
		}
		return httpHosts
	},
}

var checkCommand = &cobra.Command{ // nolint:gochecknoglobals
	PersistentPreRunE: validateSubnets,
	Use:               "diagnose",
	Short:             "Runs the network check diagnosis",
	SilenceUsage:      false,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := initAwsConfig(cmd.Context(), networkConfig.AwsRegion)
		if err != nil {
			return err
		}

		ec2Client := ec2.NewFromConfig(cfg)
		ssmClient := ssm.NewFromConfig(cfg)
		iamClient := iam.NewFromConfig(cfg)

		defer cleanup(cmd.Context(), ec2Client, iamClient)
		err = checkSMPrerequisites(cmd.Context(), ec2Client)
		if err != nil {
			return fmt.Errorf("❌ failed to check prerequisites: %v", err)
		}

		role, err := createIAMRoleAndAttachPolicy(cmd.Context(), iamClient)
		if err != nil {
			return fmt.Errorf("❌ error creating IAM role and attaching policy: %v", err)
		}
		Roles = append(Roles, *role.RoleName)
		log.Info("✅ IAM role created and policy attached")

		instanceProfile, err := createInstanceProfileAndAttachRole(cmd.Context(), iamClient, *role.RoleName)
		if err != nil {
			return fmt.Errorf("❌ failed to create instance profile: %v", err)
		}
		InstanceProfile = aws.ToString(instanceProfile.InstanceProfileName)

		allSubnets := slices.Concat(networkConfig.MainSubnets, networkConfig.PodSubnets)
		slices.Sort(allSubnets)
		distinctSubnets := slices.Compact(allSubnets)
		if len(distinctSubnets) < len(allSubnets) {
			log.Infof("ℹ️  Found duplicate subnets. We'll test each subnet '%v' only once.", distinctSubnets)
		}

		log.Info("ℹ️  Launching EC2 instances in Main subnets")
		mainInstanceIds, err := launchInstances(cmd.Context(), ec2Client, networkConfig.MainSubnets, instanceProfile.Arn)
		if err != nil {
			return err
		}
		log.Infof("ℹ️  Main EC2 instances: %v", mainInstanceIds)
		InstanceIds = append(InstanceIds, mainInstanceIds...)

		log.Info("ℹ️  Launching EC2 instances in a Pod subnets")
		podInstanceIds, err := launchInstances(cmd.Context(), ec2Client, networkConfig.PodSubnets, instanceProfile.Arn)
		if err != nil {
			return err
		}
		log.Infof("ℹ️  Pod EC2 instances: %v", podInstanceIds)
		InstanceIds = append(InstanceIds, podInstanceIds...)

		log.Info("ℹ️  Waiting for EC2 instances to become Running (times out in 5 minutes)")
		runningWaiter := ec2.NewInstanceRunningWaiter(ec2Client, func(irwo *ec2.InstanceRunningWaiterOptions) {
			irwo.MaxDelay = 15 * time.Second
			irwo.MinDelay = 5 * time.Second
		})
		err = runningWaiter.Wait(cmd.Context(), &ec2.DescribeInstancesInput{InstanceIds: InstanceIds}, *aws.Duration(5 * time.Minute))
		if err != nil {
			return fmt.Errorf("❌ Nodes never got Running: %v", err)
		}
		log.Info("✅ EC2 instances are now Running.")
		log.Info("ℹ️  Waiting for EC2 instances to become Healthy (times out in 5 minutes)")
		waitstatusOK := ec2.NewInstanceStatusOkWaiter(ec2Client, func(isow *ec2.InstanceStatusOkWaiterOptions) {
			isow.MaxDelay = 15 * time.Second
			isow.MinDelay = 5 * time.Second
		})
		err = waitstatusOK.Wait(cmd.Context(), &ec2.DescribeInstanceStatusInput{InstanceIds: InstanceIds}, *aws.Duration(5 * time.Minute))
		if err != nil {
			return fmt.Errorf("❌ Nodes never got Healthy: %v", err)
		}
		log.Info("✅ EC2 Instances are now healthy/Ok")

		log.Infof("ℹ️  Connecting to SSM...")
		err = ensureSessionManagerIsUp(cmd.Context(), ssmClient)
		if err != nil {
			return fmt.Errorf("❌ could not connect to SSM: %w", err)
		}

		log.Infof("ℹ️  Checking if the required AWS Services can be reached from the ec2 instances in the pod subnet")
		checkServicesAvailability(cmd.Context(), ssmClient, InstanceIds, testSets[TestsetNameAwsServicesPodSubnet](&networkConfig))

		log.Infof("ℹ️  Checking if certain AWS Services can be reached from ec2 instances in the main subnet")
		checkServicesAvailability(cmd.Context(), ssmClient, mainInstanceIds, testSets[TestSetNameAwsServicesMainSubnet](&networkConfig))

		httpHosts := testSets[TestSetNameHttpsHostsMainSubnet](&networkConfig)
		if len(httpHosts) > 0 {
			log.Infof("ℹ️  Checking if hosts can be reached with HTTPS from ec2 instances in the main subnets")
		}
		checkServicesAvailability(cmd.Context(), ssmClient, mainInstanceIds, httpHosts)

		return nil
	},
}

type vpcEndpointsMap struct {
	Endpoint           string
	PrivateDnsName     string
	PrivateDnsRequired bool
}

// the ssm-agent requires that ec2messages, ssm and ssmmessages are available
// we check the endpoints here so that if we cannot send commands to the ec2 instance
// in a private setup we know why
func checkSMPrerequisites(ctx context.Context, ec2Client *ec2.Client) error {
	log.Infof("ℹ️  Checking prerequisites")
	vpcEndpoints := []vpcEndpointsMap{
		{
			Endpoint:           fmt.Sprintf("com.amazonaws.%s.ec2messages", networkConfig.AwsRegion),
			PrivateDnsName:     fmt.Sprintf("ec2messages.%s.amazonaws.com", networkConfig.AwsRegion),
			PrivateDnsRequired: false,
		},
		{
			Endpoint:           fmt.Sprintf("com.amazonaws.%s.ssm", networkConfig.AwsRegion),
			PrivateDnsName:     fmt.Sprintf("ssm.%s.amazonaws.com", networkConfig.AwsRegion),
			PrivateDnsRequired: false,
		},
		{
			Endpoint:           fmt.Sprintf("com.amazonaws.%s.ssmmessages", networkConfig.AwsRegion),
			PrivateDnsName:     fmt.Sprintf("ssmmessages.%s.amazonaws.com", networkConfig.AwsRegion),
			PrivateDnsRequired: false,
		},
		{
			Endpoint:           fmt.Sprintf("com.amazonaws.%s.execute-api", networkConfig.AwsRegion),
			PrivateDnsName:     fmt.Sprintf("execute-api.%s.amazonaws.com", networkConfig.AwsRegion),
			PrivateDnsRequired: true,
		},
	}

	var prereqErrs []string
	for _, endpoint := range vpcEndpoints {
		response, err := ec2Client.DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{
			Filters: []types.Filter{
				{
					Name:   aws.String("service-name"),
					Values: []string{endpoint.Endpoint},
				},
			},
		})

		if err != nil {
			return err
		}

		if len(response.VpcEndpoints) == 0 {
			if strings.Contains(endpoint.Endpoint, "execute-api") && networkConfig.ApiEndpoint != "" {
				log.Infof("ℹ️ 'api-endpoint' parameter exists, deferring connectivity test for execute-api VPC endpoint until testing main subnet connectivity")
				continue
			} else if strings.Contains(endpoint.Endpoint, "execute-api") && networkConfig.ApiEndpoint == "" {
				errMsg := "Add a VPC endpoint for execute-api in this account or use the 'api-endpoint' parameter to specify a centralized one in another account, and test again"
				log.Errorf("❌ %s", errMsg)
				prereqErrs = append(prereqErrs, errMsg)
				continue
			}
			_, err := TestServiceConnectivity(ctx, endpoint.PrivateDnsName, 5*time.Second)
			if err != nil {
				errMsg := fmt.Sprintf("Service %s connectivity test failed: %v\n", endpoint.PrivateDnsName, err)
				log.Error("❌ %w", errMsg)
				prereqErrs = append(prereqErrs, errMsg)
			}
			log.Infof("✅ Service %s has connectivity", endpoint.PrivateDnsName)
		} else {
			for _, e := range response.VpcEndpoints {
				if e.PrivateDnsEnabled != nil && !*e.PrivateDnsEnabled && endpoint.PrivateDnsRequired {
					errMsg := fmt.Sprintf("VPC endpoint '%s' has private DNS disabled, it must be enabled", *e.VpcEndpointId)
					log.Errorf("❌ %s", errMsg)
					prereqErrs = append(prereqErrs, errMsg)
				}
			}
			log.Infof("✅ VPC endpoint %s is configured", endpoint.Endpoint)
		}
	}

	if len(prereqErrs) > 0 {
		return fmt.Errorf("%s", strings.Join(prereqErrs, "; "))
	}
	return nil
}

func ensureSessionManagerIsUp(ctx context.Context, ssmClient *ssm.Client) error {
	err := wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, 2*time.Minute, true, func(ctx context.Context) (done bool, err error) {
		_, err = sendCommand(ctx, ssmClient, "echo ssm")
		if err != nil {
			return false, nil
		}

		return true, nil
	})

	if err != nil {
		return fmt.Errorf("❌ could not establish connection with SSM: %w", err)
	}

	return nil
}

func checkServicesAvailability(ctx context.Context, ssmClient *ssm.Client, instanceIds []string, serviceEndpoints map[string]string) {
	services := make([]string, 0, len(serviceEndpoints))
	for service := range serviceEndpoints {
		services = append(services, service)
	}
	sort.Strings(services)

	for _, service := range services {
		err := isServiceAvailable(ctx, ssmClient, instanceIds, serviceEndpoints[service])
		if err != nil {
			log.Warnf("❌ %s is not available (%s)", service, serviceEndpoints[service])
			log.Info(err)
		} else {
			log.Infof("✅ %s is available", service)
		}
	}
}

func isServiceAvailable(ctx context.Context, ssmSvc *ssm.Client, instanceIds []string, serviceUrl string) error {
	commandId, err := sendServiceRequest(ctx, ssmSvc, serviceUrl)
	if err != nil {
		return fmt.Errorf("❌ Failed to run the command in instances: %v", err)
	}

	g, ctx := errgroup.WithContext(context.Background())
	for _, instanceId := range instanceIds {
		id := instanceId // Local variable for the closure
		g.Go(func() error {
			return fetchResultsForInstance(ctx, ssmSvc, id, commandId)
		})
	}
	if err := g.Wait(); err != nil {
		return fmt.Errorf("❌ Error fetching command results: %v", err)
	}

	return nil
}

func validateSubnets(cmd *cobra.Command, args []string) error {
	if len(networkConfig.MainSubnets) < 1 {
		return fmt.Errorf("❌ At least one Main subnet needs to be specified: %v", networkConfig.MainSubnets)
	}
	log.Info("✅ Main Subnets are valid")
	if len(networkConfig.PodSubnets) < 1 {
		return fmt.Errorf("❌ At least one Pod subnet needs to be specified: %v", networkConfig.PodSubnets)
	}

	log.Info("✅ Pod Subnets are valid")

	return nil
}

func launchInstances(ctx context.Context, ec2Client *ec2.Client, subnets []string, profileArn *string) ([]string, error) {
	var instanceIds []string
	for _, subnet := range subnets {
		if _, ok := Subnets[subnet]; ok {
			log.Warnf("An EC2 instance was already created for subnet '%v', skipping", subnet)
			continue
		}
		secGroup, err := createSecurityGroups(ctx, ec2Client, subnet)
		if err != nil {
			return nil, fmt.Errorf("❌ failed to create security group for subnet '%v': %v", subnet, err)
		}
		SecurityGroups = append(SecurityGroups, secGroup)

		instanceType, err := getPreferredInstanceType(ctx, ec2Client)
		if err != nil {
			return nil, fmt.Errorf("❌ failed to get preferred instance type: %v", err)
		}
		log.Infof("ℹ️  Instance type %s shall be used", instanceType)

		instanceId, err := launchInstanceInSubnet(ctx, ec2Client, subnet, secGroup, profileArn, instanceType)
		if err != nil {
			return nil, fmt.Errorf("❌ Failed to launch instances in subnet %s: %v", subnet, err)
		}

		instanceIds = append(instanceIds, instanceId)
		if Subnets == nil {
			Subnets = make(map[string]bool)
		}
		Subnets[subnet] = true
	}

	return instanceIds, nil
}

func launchInstanceInSubnet(ctx context.Context, ec2Client *ec2.Client, subnetID, secGroupId string, instanceProfileName *string, instanceType types.InstanceType) (string, error) {
	amiId := ""
	if networkConfig.InstanceAMI != "" {
		customAMIId, err := findCustomAMI(ctx, ec2Client, networkConfig.InstanceAMI)
		if err != nil {
			return "", err
		}
		amiId = customAMIId
	} else {
		regionalAMI, err := findUbuntuAMI(ctx, ec2Client)
		if err != nil {
			return "", err
		}
		amiId = regionalAMI
	}

	// Specify the user data script to install the SSM Agent
	userData := `#!/bin/bash
		sudo systemctl enable snap.amazon-ssm-agent.amazon-ssm-agent.service
		sudo systemctl restart snap.amazon-ssm-agent.amazon-ssm-agent.service
		`

	// Encode user data in base64
	userDataEncoded := base64.StdEncoding.EncodeToString([]byte(userData))

	input := &ec2.RunInstancesInput{
		ImageId:          aws.String(amiId), // Example AMI ID, replace with an actual one
		InstanceType:     instanceType,
		MaxCount:         aws.Int32(1),
		MinCount:         aws.Int32(1),
		UserData:         &userDataEncoded,
		SecurityGroupIds: []string{secGroupId},
		SubnetId:         aws.String(subnetID),
		IamInstanceProfile: &types.IamInstanceProfileSpecification{
			Arn: instanceProfileName,
		},
		TagSpecifications: []types.TagSpecification{
			{
				ResourceType: types.ResourceTypeInstance,
				Tags: []types.Tag{
					{
						Key:   aws.String("gitpod.io/network-check"),
						Value: aws.String("true"),
					},
				},
			},
		},
	}

	var result *ec2.RunInstancesOutput
	err := wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, 10*time.Second, false, func(ctx context.Context) (done bool, err error) {
		result, err = ec2Client.RunInstances(ctx, input)

		if err != nil {
			if strings.Contains(err.Error(), "Invalid IAM Instance Profile ARN") {
				return false, nil
			}

			return false, err
		}

		return true, nil
	})

	if err != nil {
		return "", err
	}

	if len(result.Instances) == 0 {
		return "", fmt.Errorf("instances didn't get created")
	}

	return aws.ToString(result.Instances[0].InstanceId), nil
}

func findCustomAMI(ctx context.Context, client *ec2.Client, amiId string) (string, error) {
	input := &ec2.DescribeImagesInput{
		ImageIds: []string{amiId},
	}

	result, err := client.DescribeImages(ctx, input)
	if err != nil {
		return "", err
	}
	if len(result.Images) > 0 {
		return *result.Images[0].ImageId, nil
	}

	return "", fmt.Errorf("no custom AMI found")
}

// findUbuntuAMI searches for the latest Ubuntu AMI in the region of the EC2 client.
func findUbuntuAMI(ctx context.Context, client *ec2.Client) (string, error) {
	// You may want to update these filters based on your specific requirements
	input := &ec2.DescribeImagesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("name"),
				Values: []string{"ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"},
			},
			{
				Name:   aws.String("virtualization-type"),
				Values: []string{"hvm"},
			},
		},
		Owners: []string{"099720109477"}, // Canonical's owner ID
	}

	result, err := client.DescribeImages(ctx, input)
	if err != nil {
		return "", err
	}

	// Sort the AMIs by creation date
	sort.Slice(result.Images, func(i, j int) bool {
		return *result.Images[i].CreationDate > *result.Images[j].CreationDate
	})

	if len(result.Images) > 0 {
		return *result.Images[0].ImageId, nil
	}

	return "", fmt.Errorf("no Ubuntu AMIs found")
}

// sendServiceRequest sends a command to an EC2 instance and returns the command ID
func sendServiceRequest(ctx context.Context, svc *ssm.Client, serviceUrl string) (string, error) {
	return sendCommand(ctx, svc, fmt.Sprintf("curl -m 15 -I %v", serviceUrl))
}

func sendCommand(ctx context.Context, svc *ssm.Client, command string) (string, error) {
	networkTestingCommands := []string{
		command,
	}

	result, err := svc.SendCommand(ctx, &ssm.SendCommandInput{
		InstanceIds:  InstanceIds,
		DocumentName: aws.String("AWS-RunShellScript"),
		Parameters: map[string][]string{
			"commands": networkTestingCommands,
		},
	})
	if err != nil {
		return "", fmt.Errorf("error sending command: %v", err)
	}

	return *result.Command.CommandId, nil
}

func fetchResultsForInstance(ctx context.Context, svc *ssm.Client, instanceId, commandId string) error {
	return wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, 30*time.Second, false, func(ctx context.Context) (done bool, err error) {
		// Check command invocation status
		invocationResult, err := svc.GetCommandInvocation(ctx, &ssm.GetCommandInvocationInput{
			CommandId:  aws.String(commandId),
			InstanceId: aws.String(instanceId),
		})

		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "InvocationDoesNotExist" {
			return false, nil
		}

		if err != nil {
			log.Errorf("❌ Error getting command invocation for instance %s: %v", instanceId, err)
			return false, fmt.Errorf("error getting command invocation for instance %s: %v", instanceId, err)
		}

		if *invocationResult.StatusDetails == "Pending" || *invocationResult.StatusDetails == "InProgress" {
			log.Debugf("⏳ Instance %s is %s for command %s", instanceId, *invocationResult.StatusDetails, commandId)
			return false, nil
		}

		if *invocationResult.StatusDetails == "Success" {
			log.Debugf("✅ Instance %s command output:\n%s\n", instanceId, *invocationResult.StandardOutputContent)
			return true, nil
		} else {
			log.Errorf("❌ Instance %s command with status %s not successful:\n%s\n", instanceId, *invocationResult.StatusDetails, *invocationResult.StandardErrorContent)
			return false, fmt.Errorf("instance %s command failed: %s", instanceId, *invocationResult.StandardErrorContent)
		}
	})
}

func createSecurityGroups(ctx context.Context, svc *ec2.Client, subnetID string) (string, error) {
	// Describe the subnet to find the VPC ID
	describeSubnetsInput := &ec2.DescribeSubnetsInput{
		SubnetIds: []string{subnetID},
	}

	describeSubnetsOutput, err := svc.DescribeSubnets(ctx, describeSubnetsInput)
	if err != nil {
		return "", fmt.Errorf("failed to describe subnet: %v", err)
	}

	if len(describeSubnetsOutput.Subnets) == 0 {
		return "", fmt.Errorf("no subnets found with ID: %s", subnetID)
	}

	vpcID := describeSubnetsOutput.Subnets[0].VpcId

	// Create the security group
	createSGInput := &ec2.CreateSecurityGroupInput{
		Description: aws.String("EC2 security group allowing all HTTPS outgoing traffic"),
		GroupName:   aws.String(fmt.Sprintf("EC2-security-group-nc-%s", subnetID)),
		VpcId:       vpcID,
		TagSpecifications: []types.TagSpecification{
			{
				ResourceType: types.ResourceTypeSecurityGroup,
				Tags: []types.Tag{
					{
						Key:   aws.String("gitpod.io/network-check"),
						Value: aws.String("true"),
					},
				},
			},
		},
	}

	createSGOutput, err := svc.CreateSecurityGroup(ctx, createSGInput)
	if err != nil {
		log.Fatalf("Failed to create security group: %v", err)
	}

	sgID := createSGOutput.GroupId
	log.Infof("ℹ️  Created security group with ID: %s", *sgID)

	// Authorize HTTPS outbound traffic
	authorizeEgressInput := &ec2.AuthorizeSecurityGroupEgressInput{
		GroupId: sgID,
		IpPermissions: []types.IpPermission{
			{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(443),
				ToPort:     aws.Int32(443),
				IpRanges: []types.IpRange{
					{
						CidrIp:      aws.String("0.0.0.0/0"),
						Description: aws.String("Allow all outbound HTTPS traffic"),
					},
				},
			},
		},
	}

	_, err = svc.AuthorizeSecurityGroupEgress(ctx, authorizeEgressInput)
	if err != nil {
		log.Fatalf("Failed to authorize security group egress: %v", err)
	}

	return *sgID, nil
}

func createIAMRoleAndAttachPolicy(ctx context.Context, svc *iam.Client) (*iam_types.Role, error) {
	// Define the trust relationship
	trustPolicy := `{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }`

	// Create the role
	createRoleOutput, err := svc.CreateRole(ctx, &iam.CreateRoleInput{
		RoleName:                 aws.String(gitpodRoleName),
		AssumeRolePolicyDocument: aws.String(trustPolicy),
		Tags:                     networkCheckTag,
	})
	if err != nil {
		return nil, fmt.Errorf("creating IAM role: %w", err)
	}

	// Attach the policy
	_, err = svc.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{
		RoleName:  aws.String(gitpodRoleName),
		PolicyArn: aws.String("arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"),
	})
	if err != nil {
		return nil, fmt.Errorf("attaching policy to role: %w", err)
	}

	return createRoleOutput.Role, nil
}

func createInstanceProfileAndAttachRole(ctx context.Context, svc *iam.Client, roleName string) (*iam_types.InstanceProfile, error) {
	// Create instance profile
	instanceProfileOutput, err := svc.CreateInstanceProfile(ctx, &iam.CreateInstanceProfileInput{
		InstanceProfileName: aws.String(gitpodInstanceProfile),
		Tags:                networkCheckTag,
	})
	if err != nil {
		return nil, fmt.Errorf("creating instance profile: %w", err)
	}

	// Add role to instance profile
	_, err = svc.AddRoleToInstanceProfile(ctx, &iam.AddRoleToInstanceProfileInput{
		InstanceProfileName: aws.String(gitpodInstanceProfile),
		RoleName:            aws.String(roleName),
	})
	if err != nil {
		return nil, fmt.Errorf("adding role to instance profile: %w", err)
	}

	return instanceProfileOutput.InstanceProfile, nil
}

func getPreferredInstanceType(ctx context.Context, svc *ec2.Client) (types.InstanceType, error) {
	instanceTypes := []types.InstanceType{
		types.InstanceTypeT2Micro,
		types.InstanceTypeT3aMicro,
		types.InstanceTypeT3Micro,
	}
	for _, instanceType := range instanceTypes {
		exists, err := instanceTypeExists(ctx, svc, instanceType)
		if err != nil {
			return "", err
		}
		if exists {
			return instanceType, nil
		}
	}
	return "", fmt.Errorf("no preferred instance type available in region: %s", networkConfig.AwsRegion)
}

func instanceTypeExists(ctx context.Context, svc *ec2.Client, instanceType types.InstanceType) (bool, error) {
	input := &ec2.DescribeInstanceTypeOfferingsInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("instance-type"),
				Values: []string{string(instanceType)},
			},
		},
		LocationType: types.LocationTypeRegion,
	}

	resp, err := svc.DescribeInstanceTypeOfferings(ctx, input)
	if err != nil {
		return false, err
	}

	return len(resp.InstanceTypeOfferings) > 0, nil
}

// ConnectivityTestResult represents the results of DNS and network connectivity tests
type ConnectivityTestResult struct {
	IPAddresses []string
}

// TestServiceConnectivity tests both DNS resolution and TCP connectivity given a hostname
func TestServiceConnectivity(ctx context.Context, hostname string, timeout time.Duration) (*ConnectivityTestResult, error) {
	result := &ConnectivityTestResult{}

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		return result, fmt.Errorf("DNS resolution failed: %w", err)
	}
	for _, ip := range ips {
		result.IPAddresses = append(result.IPAddresses, ip.String())
	}
	if len(result.IPAddresses) == 0 {
		return result, fmt.Errorf("no IP addresses found for hostname: %s", hostname)
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:443", result.IPAddresses[0]))
	if err != nil {
		return result, fmt.Errorf("TCP connection failed: %w", err)
	}
	defer conn.Close()

	return result, nil
}
