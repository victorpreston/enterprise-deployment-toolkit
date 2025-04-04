package runner

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"net"
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
	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/gitpod-io/enterprise-deployment-toolkit/gitpod-network-check/pkg/checks"
)

const gitpodRoleName = "GitpodNetworkCheck"
const gitpodInstanceProfile = "GitpodNetworkCheck"

type EC2TestRunner struct {
	networkConfig *checks.NetworkConfig

	ec2Client *ec2.Client
	ssmClient *ssm.Client
	iamClient *iam.Client

	roles           []string
	securityGroups  []string
	instanceProfile *iam_types.InstanceProfile
	instanceIds     map[string]string
}

func NewEC2TestRunner(ctx context.Context, networkConfig *checks.NetworkConfig) (*EC2TestRunner, error) {
	cfg, err := initAwsConfig(ctx, networkConfig.AwsRegion)
	if err != nil {
		return nil, err
	}

	ec2Client := ec2.NewFromConfig(cfg)
	ssmClient := ssm.NewFromConfig(cfg)
	iamClient := iam.NewFromConfig(cfg)

	return &EC2TestRunner{
		networkConfig: networkConfig,

		ec2Client: ec2Client,
		ssmClient: ssmClient,
		iamClient: iamClient,

		roles:          []string{},
		securityGroups: []string{},
		instanceIds:    make(map[string]string),
	}, nil
}

// create IAM role, attach policy, instance profile and attach role
func (r *EC2TestRunner) Prepare(ctx context.Context) error {
	err := checkSMPrerequisites(ctx, r.networkConfig, r.ec2Client)
	if err != nil {
		return fmt.Errorf("failed to check prerequisites: %v", err)
	}

	// Prepare EC2 instance creation
	role, err := createIAMRoleAndAttachPolicy(ctx, r.iamClient)
	if err != nil {
		return fmt.Errorf("error creating IAM role and attaching policy: %v", err)
	}
	r.roles = append(r.roles, *role.RoleName)
	log.Info("✅ IAM role created and policy attached")

	instanceProfile, err := createInstanceProfileAndAttachRole(ctx, r.iamClient, *role.RoleName)
	if err != nil {
		return fmt.Errorf("failed to create instance profile: %v", err)
	}
	r.instanceProfile = instanceProfile

	// Lazy initialization of the EC2 instances
	subnets := r.networkConfig.GetAllSubnets()
	for _, subnet := range subnets {
		_, err := r.ensureEC2Instance(ctx, subnet)
		if err != nil {
			return err
		}
	}
	log.Infof("✅ EC2 instances launched for subnets: %s", checks.Subnets(subnets).String())

	return nil
}

// the ssm-agent requires that ec2messages, ssm and ssmmessages are available
// we check the endpoints here so that if we cannot send commands to the ec2 instance
// in a private setup we know why
func checkSMPrerequisites(ctx context.Context, networkConfig *checks.NetworkConfig, ec2Client *ec2.Client) error {
	type vpcEndpointsMap struct {
		Endpoint           string
		PrivateDnsName     string
		PrivateDnsRequired bool
	}

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

func (r *EC2TestRunner) ensureEC2Instance(ctx context.Context, subnet checks.Subnet) (string, error) {
	launchInstance := func(ctx context.Context, subnet checks.Subnet) (string, error) {
		log.Infof("ℹ️  Launching EC2 instance in subnet: %s", subnet.String())
		secGroup, err := createSecurityGroups(ctx, r.ec2Client, subnet.SubnetID)
		if err != nil {
			return "", fmt.Errorf("failed to create security group for subnet '%v': %v", subnet, err)
		}
		r.securityGroups = append(r.securityGroups, secGroup)

		instanceType, err := getPreferredInstanceType(ctx, r.ec2Client, r.networkConfig)
		if err != nil {
			return "", fmt.Errorf("failed to get preferred instance type: %v", err)
		}
		log.Infof("ℹ️  Instance type %s shall be used", instanceType)

		instanceId, err := launchInstanceInSubnet(ctx, r.ec2Client, subnet.SubnetID, secGroup, r.instanceProfile.Arn, instanceType, r.networkConfig.InstanceAMI)
		if err != nil {
			return "", fmt.Errorf("Failed to launch instances in subnet %s: %v", subnet, err)
		}
		return instanceId, nil
	}

	if existingInstanceId, exists := r.instanceIds[subnet.SubnetID]; exists {
		log.Infof("ℹ️  Instance %s already exists in subnet %s, skipping launch", existingInstanceId, subnet.String())
		return existingInstanceId, nil
	}

	instanceId, err := launchInstance(ctx, subnet)
	if err != nil {
		return "", fmt.Errorf("failed to launch instance in subnet %s: %v", subnet.String(), err)
	}
	r.instanceIds[subnet.SubnetID] = instanceId
	log.Infof("ℹ️  Launched instance %s in subnet %s", instanceId, subnet.String())

	return instanceId, nil
}

func (r *EC2TestRunner) TestService(ctx context.Context, subnets []checks.Subnet, serviceEndpoints map[string]string) (bool, error) {
	// Make sure we have one instance per subnet
	instanceIds := []string{}
	for _, subnet := range subnets {
		instanceId, err := r.ensureEC2Instance(ctx, subnet)
		if err != nil {
			return false, err
		}
		instanceIds = append(instanceIds, instanceId)
	}

	err := r.checkAllInstancesAvailable(ctx, instanceIds)
	if err != nil {
		return false, err
	}

	// Actually test the service
	testResult := r.checkServicesAvailability(ctx, instanceIds, serviceEndpoints)
	return testResult, nil
}

func (r *EC2TestRunner) checkAllInstancesAvailable(ctx context.Context, instanceIds []string) error {
	// Wait until all instances are running
	log.WithField("instanceIds", instanceIds).Info("ℹ️  Waiting for EC2 instances to become Running (times out in 5 minutes)")
	runningWaiter := ec2.NewInstanceRunningWaiter(r.ec2Client, func(irwo *ec2.InstanceRunningWaiterOptions) {
		irwo.MaxDelay = 15 * time.Second
		irwo.MinDelay = 5 * time.Second
		irwo.LogWaitAttempts = true
	})
	err := runningWaiter.Wait(ctx, &ec2.DescribeInstancesInput{InstanceIds: instanceIds}, *aws.Duration(5 * time.Minute))
	if err != nil {
		return fmt.Errorf("Nodes never got Running: %v", err)
	}

	log.Info("✅ EC2 instances are now Running.")
	log.Info("ℹ️  Waiting for EC2 instances to become Healthy (times out in 5 minutes)")
	waitstatusOK := ec2.NewInstanceStatusOkWaiter(r.ec2Client, func(isow *ec2.InstanceStatusOkWaiterOptions) {
		isow.MaxDelay = 15 * time.Second
		isow.MinDelay = 5 * time.Second
	})
	err = waitstatusOK.Wait(ctx, &ec2.DescribeInstanceStatusInput{InstanceIds: instanceIds}, *aws.Duration(5 * time.Minute))
	if err != nil {
		return fmt.Errorf("Nodes never got Healthy: %v", err)
	}
	log.Info("✅ EC2 Instances are now healthy/Ok")

	log.Infof("ℹ️  Connecting to SSM...")
	err = ensureSessionManagerIsUp(ctx, r.ssmClient, instanceIds)
	if err != nil {
		return fmt.Errorf("could not connect to SSM: %w", err)
	}
	log.Infof("✅ SSM is up and running")

	return nil
}

func (r *EC2TestRunner) checkServicesAvailability(ctx context.Context, instanceIds []string, serviceEndpoints map[string]string) bool {
	services := make([]string, 0, len(serviceEndpoints))
	for service := range serviceEndpoints {
		services = append(services, service)
	}
	sort.Strings(services)

	result := true
	for _, service := range services {
		err := r.isServiceAvailable(ctx, instanceIds, serviceEndpoints[service])
		if err != nil {
			log.Warnf("❌ %s is not available (%s)", service, serviceEndpoints[service])
			log.Info(err)
			result = false
		} else {
			log.Infof("✅ %s is available", service)
		}
	}
	return result
}

func (r *EC2TestRunner) isServiceAvailable(ctx context.Context, instanceIds []string, serviceUrl string) error {
	commandId, err := sendServiceRequest(ctx, r.ssmClient, instanceIds, serviceUrl)
	if err != nil {
		return fmt.Errorf("Failed to run the command in instances: %v", err)
	}

	g, ctx := errgroup.WithContext(context.Background())
	for _, instanceId := range instanceIds {
		id := instanceId // Local variable for the closure
		g.Go(func() error {
			return fetchResultsForInstance(ctx, r.ssmClient, id, commandId)
		})
	}
	if err := g.Wait(); err != nil {
		return fmt.Errorf("Error fetching command results: %v", err)
	}

	return nil
}

func launchInstanceInSubnet(ctx context.Context, ec2Client *ec2.Client, subnetID, secGroupId string, instanceProfileName *string, instanceType types.InstanceType, instanceAMI string) (string, error) {
	amiId := ""
	if instanceAMI != "" {
		customAMIId, err := findCustomAMI(ctx, ec2Client, instanceAMI)
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
				Tags:         NetworkCheckEC2Tags,
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

func ensureSessionManagerIsUp(ctx context.Context, ssmClient *ssm.Client, instanceIds []string) error {
	err := wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, 2*time.Minute, true, func(ctx context.Context) (done bool, err error) {
		_, err = sendCommand(ctx, ssmClient, instanceIds, "echo ssm")
		if err != nil {
			return false, nil
		}

		return true, nil
	})

	if err != nil {
		return fmt.Errorf("could not establish connection with SSM: %w", err)
	}

	return nil
}

// Creates a new EC2TestRunner instance, loading existing resources from the AWS account by known name/tags
func LoadEC2RunnerFromTags(ctx context.Context, networkConfig *checks.NetworkConfig) (*EC2TestRunner, error) {
	runner, err := NewEC2TestRunner(ctx, networkConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create EC2TestRunner: %v", err)
	}
	svc := runner.ec2Client

	// load instanceIds
	instances, err := svc.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		Filters: append(NetworkCheckTagsFilter, types.Filter{
			Name:   aws.String("instance-state-name"),
			Values: []string{"pending", "running", "shutting-down", "stopping", "stopped"},
		},
		),
	})
	if err != nil {
		log.WithError(err).Error("Failed to list instances, please cleanup instances manually")
	} else if len(instances.Reservations) == 0 {
		log.Info("No instances found.")
	}
	if instances != nil {
		for _, r := range instances.Reservations {
			for _, i := range r.Instances {
				runner.instanceIds[*i.SubnetId] = *i.InstanceId
			}
		}
	}

	// load roles
	paginator := iam.NewListInstanceProfilesPaginator(runner.iamClient, &iam.ListInstanceProfilesInput{})
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			log.WithError(err).Warn("Failed to list roles, please cleanup manually")
			break
		}

		for _, ip := range output.InstanceProfiles {
			if *ip.InstanceProfileName == gitpodInstanceProfile {
				{
					runner.instanceProfile = &ip
					if len(ip.Roles) > 0 {
						for _, role := range ip.Roles {
							runner.roles = append(runner.roles, *role.RoleName)
						}
					}
				}

			}
		}
	}
	if len(runner.roles) == 0 {
		log.Info("No roles found.")
	}

	// load security groups
	securityGroups, err := svc.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		Filters: NetworkCheckTagsFilter,
	})

	if err != nil {
		log.WithError(err).Error("Failed to list security groups, please cleanup manually")
	} else if len(securityGroups.SecurityGroups) == 0 {
		log.Info("No security groups found.")
	}

	if securityGroups != nil {
		for _, sg := range securityGroups.SecurityGroups {
			runner.securityGroups = append(runner.securityGroups, *sg.GroupId)
		}
	}

	return runner, nil
}

func (r *EC2TestRunner) Cleanup(ctx context.Context) error {
	// delete instances
	instanceIds := slices.Collect(maps.Values(r.instanceIds))
	if len(instanceIds) != 0 {
		log.Info("ℹ️  Terminating EC2 instances")
		_, err := r.ec2Client.TerminateInstances(ctx, &ec2.TerminateInstancesInput{
			InstanceIds: instanceIds,
		})
		if err != nil {
			log.WithError(err).WithField("instanceIds", instanceIds).Warnf("Failed to cleanup instances, please cleanup manually")
		}

		terminateWaiter := ec2.NewInstanceTerminatedWaiter(r.ec2Client, func(itwo *ec2.InstanceTerminatedWaiterOptions) {
			itwo.MaxDelay = 15 * time.Second
			itwo.MinDelay = 5 * time.Second
		})
		log.Info("ℹ️  Waiting for EC2 instances to Terminate (times out in 5 minutes)")
		err = terminateWaiter.Wait(ctx, &ec2.DescribeInstancesInput{InstanceIds: instanceIds}, *aws.Duration(5 * time.Minute))
		if err != nil {
			log.WithError(err).Warn("Failed to wait for instances to terminate")
			log.Warn("ℹ️  Waiting 2 minutes so network interfaces are deleted")
			time.Sleep(2 * time.Minute)
		} else {
			log.Info("✅ Instances terminated")
		}
	}

	// delete roles
	instanceProfileName := ""
	if r.instanceProfile != nil {
		instanceProfileName = *r.instanceProfile.InstanceProfileName
	}

	if instanceProfileName != "" {
		log.WithField("instanceProfileName", instanceProfileName).Info("ℹ️  Deleting instance profile...")
		for _, role := range r.roles {
			_, err := r.iamClient.DetachRolePolicy(ctx, &iam.DetachRolePolicyInput{PolicyArn: aws.String("arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"), RoleName: aws.String(role)})
			if err != nil && errorCode(err) != "NoSuchEntity" {
				log.WithError(err).WithField("rolename", role).Warnf("Failed to cleanup role, please cleanup manually")
			}

			_, err = r.iamClient.RemoveRoleFromInstanceProfile(ctx, &iam.RemoveRoleFromInstanceProfileInput{
				RoleName:            aws.String(role),
				InstanceProfileName: aws.String(instanceProfileName),
			})
			if err != nil {
				log.WithError(err).WithField("roleName", role).WithField("instanceProfileName", instanceProfileName).Warnf("Failed to remove role from instance profile")
			}

			_, err = r.iamClient.DeleteRole(ctx, &iam.DeleteRoleInput{RoleName: aws.String(role)})
			if err != nil && errorCode(err) != "NoSuchEntity" {
				log.WithError(err).WithField("rolename", role).Warnf("Failed to cleanup role, please cleanup manually")
				continue
			}

			log.Infof("✅ Role '%v' deleted", role)
		}

		_, err := r.iamClient.DeleteInstanceProfile(ctx, &iam.DeleteInstanceProfileInput{
			InstanceProfileName: aws.String(instanceProfileName),
		})

		if err != nil && errorCode(err) != "NoSuchEntity" {
			log.WithError(err).WithField("instanceProfileName", instanceProfileName).Warnf("Failed to clean up instance profile, please cleanup manually")
		} else {
			log.WithField("instanceProfileName", instanceProfileName).Info("✅ Instance profile deleted")
		}
	}

	// delete security groups
	for _, sg := range r.securityGroups {
		deleteSGInput := &ec2.DeleteSecurityGroupInput{
			GroupId: aws.String(sg),
		}

		_, err := r.ec2Client.DeleteSecurityGroup(ctx, deleteSGInput)
		if err != nil {
			log.WithError(err).WithField("securityGroup", sg).Warnf("Failed to clean up security group, please cleanup manually")
			continue
		}
		log.Infof("✅ Security group '%v' deleted", sg)
	}

	return nil
}

func errorCode(err error) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode()
	}
	return ""
}

// sendServiceRequest sends a command to an EC2 instance and returns the command ID
func sendServiceRequest(ctx context.Context, svc *ssm.Client, instanceIds []string, serviceUrl string) (string, error) {
	return sendCommand(ctx, svc, instanceIds, fmt.Sprintf("curl -m 15 -I %v", serviceUrl))
}

func sendCommand(ctx context.Context, svc *ssm.Client, instanceIds []string, command string) (string, error) {
	networkTestingCommands := []string{
		command,
	}

	result, err := svc.SendCommand(ctx, &ssm.SendCommandInput{
		InstanceIds:  instanceIds,
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
				Tags:         NetworkCheckEC2Tags,
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
		Tags:                     NetworkCheckIamTags,
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
		Tags:                NetworkCheckIamTags,
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

func getPreferredInstanceType(ctx context.Context, svc *ec2.Client, networkConfig *checks.NetworkConfig) (types.InstanceType, error) {
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
