# Gitpod Network Check CloudFormation Template

This CloudFormation template deploys an EC2 instance that runs the gitpod-network-check tool to validate if your AWS network setup is suitable for Gitpod installation.

## Overview

The template creates the following resources:
- IAM roles and instance profile for the EC2 instance
- Security group allowing outbound HTTPS traffic
- EC2 instance that runs the gitpod-network-check tool

## Prerequisites

1. AWS CLI installed and configured with appropriate credentials
2. VPC and subnets already created (both main and pod subnets)
3. Permissions to create IAM roles and EC2 instances

## Deployment Instructions

### Option 1: Using the Deployment Script (Recommended)

The easiest way to deploy this template is to use the provided deployment script:

```bash
cd gitpod-network-check/cft-ec2/
./deploy-network-check.sh
```

See the `DEPLOYMENT.md` file for more details.

### Option 2: AWS Management Console

1. Log in to the AWS Management Console
2. Navigate to CloudFormation
3. Click "Create stack" > "With new resources (standard)"
4. Choose "Upload a template file" and upload the `gitpod-network-check-cfn.yaml` file from the `gitpod-network-check/cft-ec2/` directory
5. Click "Next"
6. Enter a stack name (e.g., `gitpod-network-check`)
7. Configure the parameters:
   - Region: AWS region to deploy in (e.g., `eu-central-1`)
   - VpcId: The VPC ID where resources will be deployed
   - MainSubnets: Comma-separated list of main subnet IDs (e.g., `subnet-123,subnet-456`)
   - PodSubnets: Comma-separated list of pod subnet IDs (e.g., `subnet-789,subnet-012`)
   - HttpsHosts: Comma-separated list of HTTPS hosts to test (default: `accounts.google.com,github.com`)
   - InstanceAMI: (Optional) Custom AMI ID
   - ApiEndpoint: (Optional) API endpoint regional subdomain
   - LogLevel: Log level for the tool (default: `debug`)
   - InstanceType: EC2 instance type (default: `t2.micro`)
8. Click "Next", configure any stack options, and click "Next" again
9. Review the configuration and click "Create stack"

### Option 3: AWS CLI

```bash
cd gitpod-network-check/cft-ec2/
aws cloudformation create-stack \
  --stack-name gitpod-network-check \
  --template-body file://gitpod-network-check-cfn.yaml \
  --parameters \
    ParameterKey=Region,ParameterValue=eu-central-1 \
    ParameterKey=VpcId,ParameterValue=vpc-12345678 \
    ParameterKey=MainSubnets,ParameterValue=subnet-123,subnet-456 \
    ParameterKey=PodSubnets,ParameterValue=subnet-789,subnet-012 \
    ParameterKey=HttpsHosts,ParameterValue=accounts.google.com,github.com \
    ParameterKey=LogLevel,ParameterValue=debug \
    ParameterKey=InstanceType,ParameterValue=t2.micro \
  --capabilities CAPABILITY_NAMED_IAM
```

## Viewing Results

The network check results are stored in a log file on the EC2 instance. You can access the results in several ways:

1. **Using SSM Session Manager**:
   - Navigate to the CloudFormation stack outputs
   - Click on the SSMSessionURL link to start a session with the instance
   - Run `cat /var/log/gitpod-network-check.log` to view the results

2. **Using AWS CLI**:
   - Use the ViewLogsCommand provided in the stack outputs:
   ```bash
   aws ssm start-session --target i-1234567890abcdef0 --document-name AWS-StartInteractiveCommand --parameters command="cat /var/log/gitpod-network-check.log" --region eu-central-1
   ```

## Cleanup

When you're done with the network check, you can delete the CloudFormation stack to clean up all resources:

```bash
aws cloudformation delete-stack --stack-name gitpod-network-check
```

## Troubleshooting

1. **Stack creation fails**:
   - Check the CloudFormation events for error messages
   - Verify that the VPC ID and subnet IDs are valid and in the specified region
   - Ensure you have the necessary permissions to create all resources

2. **Network check fails**:
   - Connect to the instance using SSM Session Manager
   - Check the log file at `/var/log/gitpod-network-check.log` for error messages
   - Verify that the subnets have proper routing and security group configurations

3. **Cannot connect to the instance**:
   - Verify that the instance is running
   - Check that the SSM agent is running on the instance
   - Ensure the instance has outbound internet connectivity
