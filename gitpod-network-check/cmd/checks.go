package cmd

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
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

const gitpodRoleName = "GitpodNetworkCheck"
const gitpodInstanceProfile = "GitpodNetworkCheck"

var networkCheckTag = []iam_types.Tag{
	{
		Key:   aws.String("gitpod.io/network-check"),
		Value: aws.String("true"),
	},
}

func initAwsConfig(ctx context.Context, region string) (aws.Config, error) {
	return config.LoadDefaultConfig(ctx, config.WithRegion(region))
}

// this will be useful when we are cleaning up things at the end
var (
	InstanceIds     []string
	SecurityGroups  []string
	Roles           []string
	InstanceProfile string
)

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

		instanceProfile, err := createInstanceProfileAndAttachRole(cmd.Context(), iamClient, *role.RoleName)
		if err != nil {
			return fmt.Errorf("❌ failed to create instance profile: %v", err)
		}
		InstanceProfile = aws.ToString(instanceProfile.InstanceProfileName)

		log.Infof("ℹ️  Launching EC2 instances in Main subnets")
		mainInstanceIds, err := launchInstances(cmd.Context(), ec2Client, networkConfig.MainSubnets, instanceProfile.Arn)
		if err != nil {
			return err
		}
		InstanceIds = append(InstanceIds, mainInstanceIds...)

		log.Infof("ℹ️  Launching EC2 instances in a Pod subnets")
		podInstanceIds, err := launchInstances(cmd.Context(), ec2Client, networkConfig.PodSubnets, instanceProfile.Arn)
		if err != nil {
			return err
		}
		InstanceIds = append(InstanceIds, podInstanceIds...)

		log.Infof("ℹ️  Waiting for EC2 instances to become ready (can take up to 2 minutes)")
		waiter := ec2.NewInstanceRunningWaiter(ec2Client, func(irwo *ec2.InstanceRunningWaiterOptions) {
			irwo.MaxDelay = 15 * time.Second
			irwo.MinDelay = 5 * time.Second
		})
		err = waiter.Wait(cmd.Context(), &ec2.DescribeInstancesInput{InstanceIds: InstanceIds}, *aws.Duration(4 * time.Minute))
		if err != nil {
			return fmt.Errorf("❌ Nodes never got ready: %v", err)
		}
		log.Info("✅ EC2 Instances are now running successfully")

		log.Infof("ℹ️  Connecting to SSM...")
		err = ensureSessionManagerIsUp(cmd.Context(), ssmClient)
		if err != nil {
			return fmt.Errorf("❌ could not connect to SSM: %w", err)
		}

		log.Infof("ℹ️  Checking if the required AWS Services can be reached from the ec2 instances")
		serviceEndpoints := map[string]string{
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
		checkServicesAvailability(cmd.Context(), ssmClient, InstanceIds, serviceEndpoints)

		serviceEndpointsForMain := map[string]string{
			"S3":       fmt.Sprintf("https://s3.%s.amazonaws.com", networkConfig.AwsRegion),
			"DynamoDB": fmt.Sprintf("https://dynamodb.%s.amazonaws.com", networkConfig.AwsRegion),
		}
		checkServicesAvailability(cmd.Context(), ssmClient, mainInstanceIds, serviceEndpointsForMain)

		return nil
	},
}

type vpcEndpointsMap struct {
	Endpoint string
	Required bool
}

// the ssm-agent requires that ec2messages, ssm and ssmmessages are available
// we check the endpoints here so that if we cannot send commands to the ec2 instance
// in a private setup we know why
func checkSMPrerequisites(ctx context.Context, ec2Client *ec2.Client) error {
	log.Infof("ℹ️  Checking prerequisites")
	vpcEndpoints := []vpcEndpointsMap{
		{
			Endpoint: fmt.Sprintf("com.amazonaws.%s.ec2messages", networkConfig.AwsRegion),
			Required: false,
		},
		{
			Endpoint: fmt.Sprintf("com.amazonaws.%s.ssm", networkConfig.AwsRegion),
			Required: false,
		},
		{
			Endpoint: fmt.Sprintf("com.amazonaws.%s.ssmmessages", networkConfig.AwsRegion),
			Required: false,
		},
		{
			Endpoint: fmt.Sprintf("com.amazonaws.%s.execute-api", networkConfig.AwsRegion),
			Required: true,
		},
	}

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
			if endpoint.Required {
				return fmt.Errorf("❌ VPC endpoint %s not configured: %w", endpoint.Endpoint, err)
			}
			log.Infof("ℹ️  VPC endpoint %s is not configured", endpoint.Endpoint)
		} else {
			log.Infof("✅ VPC endpoint %s is configured", endpoint.Endpoint)
		}
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
		secGroup, err := createSecurityGroups(ctx, ec2Client, subnet)
		if err != nil {
			return nil, fmt.Errorf("❌ failed to create security group: %v", err)
		}
		SecurityGroups = append(SecurityGroups, secGroup)
		instanceId, err := launchInstanceInSubnet(ctx, ec2Client, subnet, secGroup, profileArn)
		if err != nil {
			return nil, fmt.Errorf("❌ Failed to launch instances in subnet %s: %v", subnet, err)
		}

		instanceIds = append(instanceIds, instanceId)
	}

	return instanceIds, nil
}

func launchInstanceInSubnet(ctx context.Context, ec2Client *ec2.Client, subnetID, secGroupId string, instanceProfileName *string) (string, error) {
	regionalAMI, err := findUbuntuAMI(ctx, ec2Client)
	if err != nil {
		return "", err
	}

	// Specify the user data script to install the SSM Agent
	userData := `#!/bin/bash
		sudo systemctl enable snap.amazon-ssm-agent.amazon-ssm-agent.service
		sudo systemctl restart snap.amazon-ssm-agent.amazon-ssm-agent.service
		`

	// Encode user data in base64
	userDataEncoded := base64.StdEncoding.EncodeToString([]byte(userData))

	input := &ec2.RunInstancesInput{
		ImageId:          aws.String(regionalAMI), // Example AMI ID, replace with an actual one
		InstanceType:     types.InstanceTypeT2Micro,
		MaxCount:         aws.Int32(1),
		MinCount:         aws.Int32(1),
		UserData:         &userDataEncoded,
		SecurityGroupIds: []string{secGroupId},
		SubnetId:         aws.String(subnetID),
		IamInstanceProfile: &types.IamInstanceProfileSpecification{
			Arn: instanceProfileName,
		},
	}

	var result *ec2.RunInstancesOutput
	err = wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, 10*time.Second, false, func(ctx context.Context) (done bool, err error) {
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
			return false, fmt.Errorf("error getting command invocation for instance %s: %v", instanceId, err)
		}

		if *invocationResult.StatusDetails == "Pending" || *invocationResult.StatusDetails == "InProgress" {
			return false, nil
		}

		if *invocationResult.StatusDetails == "Success" {
			log.Debugf("✅ Instance %s command output:\n%s\n", instanceId, *invocationResult.StandardOutputContent)
			return true, nil
		} else {
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
		return "", fmt.Errorf("Failed to describe subnet: %v", err)
	}

	if len(describeSubnetsOutput.Subnets) == 0 {
		return "", fmt.Errorf("No subnets found with ID: %s", subnetID)
	}

	vpcID := describeSubnetsOutput.Subnets[0].VpcId

	// Create the security group
	createSGInput := &ec2.CreateSecurityGroupInput{
		Description: aws.String("EC2 security group allowing all HTTPS outgoing traffic"),
		GroupName:   aws.String(fmt.Sprintf("EC2-security-group-nc-%s", subnetID)),
		VpcId:       vpcID,
	}

	createSGOutput, err := svc.CreateSecurityGroup(ctx, createSGInput)
	if err != nil {
		log.Fatalf("Failed to create security group: %v", err)
	}

	sgID := createSGOutput.GroupId
	log.Infof("ℹ️ Created security group with ID: %s", *sgID)

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

func cleanup(ctx context.Context, svc *ec2.Client, iamsvc *iam.Client) {
	if len(InstanceIds) > 0 {
		_, err := svc.TerminateInstances(ctx, &ec2.TerminateInstancesInput{
			InstanceIds: InstanceIds,
		})
		if err != nil {
			log.WithError(err).WithField("instanceIds", InstanceIds).Warnf("Failed to cleanup instances, please cleanup manually")
		}
	}
	if len(Roles) > 0 {
		for _, role := range Roles {
			_, err := iamsvc.DetachRolePolicy(ctx, &iam.DetachRolePolicyInput{PolicyArn: aws.String("arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"), RoleName: aws.String(role)})
			if err != nil {
				log.WithError(err).WithField("rolename", role).Warnf("Failed to cleanup role, please cleanup manually")
			}

			_, err = iamsvc.RemoveRoleFromInstanceProfile(ctx, &iam.RemoveRoleFromInstanceProfileInput{
				RoleName:            aws.String(role),
				InstanceProfileName: aws.String(InstanceProfile),
			})
			if err != nil {
				log.WithError(err).WithField("roleName", role).WithField("profileName", InstanceProfile).Warnf("Failed to remove role from instance profile")
			}

			_, err = iamsvc.DeleteRole(ctx, &iam.DeleteRoleInput{RoleName: aws.String(role)})
			if err != nil {
				log.WithError(err).WithField("rolename", role).Warnf("Failed to cleanup role, please cleanup manaullay")
			}
		}

		_, err := iamsvc.DeleteInstanceProfile(ctx, &iam.DeleteInstanceProfileInput{
			InstanceProfileName: aws.String(InstanceProfile),
		})

		if err != nil {
			log.WithError(err).WithField("instanceProfile", InstanceProfile).Warnf("Failed to clean up instance profile, please cleanup manually")
		}
	}

	log.Info("Cleaning up: Waiting for 1 minute so network interfaces are deleted")
	time.Sleep(time.Minute)

	if len(SecurityGroups) > 0 {
		for _, sg := range SecurityGroups {
			deleteSGInput := &ec2.DeleteSecurityGroupInput{
				GroupId: aws.String(sg),
			}

			_, err := svc.DeleteSecurityGroup(ctx, deleteSGInput)
			if err != nil {
				log.WithError(err).WithField("securityGroup", sg).Warnf("Failed to clean up security group, please cleanup manually")
			}

		}

	}
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
