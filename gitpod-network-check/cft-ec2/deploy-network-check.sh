#!/bin/bash

# Colors for better readability
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
TEMPLATE_PATH="$SCRIPT_DIR/gitpod-network-check-cfn.yaml"

echo -e "${GREEN}Gitpod Network Check - CloudFormation Deployment Script${NC}"
echo "This script will deploy a CloudFormation stack to run the gitpod-network-check tool."
echo

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo -e "${RED}Error: AWS CLI is not installed. Please install it first.${NC}"
    exit 1
fi

# Check if jq is installed (for parsing AWS CLI output)
if ! command -v jq &> /dev/null; then
    echo -e "${YELLOW}Warning: jq is not installed. Some output formatting may be limited.${NC}"
fi

# Get stack name
read -p "Enter a name for the CloudFormation stack [gitpod-network-check]: " STACK_NAME
STACK_NAME=${STACK_NAME:-gitpod-network-check}

# Get AWS region
read -p "Enter AWS region [eu-central-1]: " REGION
REGION=${REGION:-eu-central-1}

# Get VPC ID
read -p "Enter VPC ID where resources will be deployed: " VPC_ID
if [ -z "$VPC_ID" ]; then
    echo -e "${RED}Error: VPC ID is required.${NC}"
    exit 1
fi

# Get main subnets
read -p "Enter comma-separated list of main subnet IDs (e.g., subnet-123,subnet-456): " MAIN_SUBNETS
if [ -z "$MAIN_SUBNETS" ]; then
    echo -e "${RED}Error: Main subnets are required.${NC}"
    exit 1
fi

# Get pod subnets
read -p "Enter comma-separated list of pod subnet IDs (e.g., subnet-789,subnet-012): " POD_SUBNETS
if [ -z "$POD_SUBNETS" ]; then
    echo -e "${RED}Error: Pod subnets are required.${NC}"
    exit 1
fi

# Get HTTPS hosts (optional)
read -p "Enter comma-separated list of HTTPS hosts to test [accounts.google.com,github.com]: " HTTPS_HOSTS
HTTPS_HOSTS=${HTTPS_HOSTS:-accounts.google.com,github.com}

# Get custom AMI (optional)
read -p "Enter custom AMI ID (leave empty to use default Ubuntu AMI): " INSTANCE_AMI

# Get API endpoint (optional)
read -p "Enter API endpoint regional subdomain (optional): " API_ENDPOINT

# Get log level
read -p "Enter log level (debug, info, warning, error) [debug]: " LOG_LEVEL
LOG_LEVEL=${LOG_LEVEL:-debug}

# Get instance type
read -p "Enter EC2 instance type (t2.micro, t3.micro, t3a.micro) [t2.micro]: " INSTANCE_TYPE
INSTANCE_TYPE=${INSTANCE_TYPE:-t2.micro}

echo
echo -e "${YELLOW}Review the following parameters:${NC}"
echo "Stack Name: $STACK_NAME"
echo "Region: $REGION"
echo "VPC ID: $VPC_ID"
echo "Main Subnets: $MAIN_SUBNETS"
echo "Pod Subnets: $POD_SUBNETS"
echo "HTTPS Hosts: $HTTPS_HOSTS"
echo "Instance AMI: ${INSTANCE_AMI:-<default>}"
echo "API Endpoint: ${API_ENDPOINT:-<none>}"
echo "Log Level: $LOG_LEVEL"
echo "Instance Type: $INSTANCE_TYPE"
echo

read -p "Do you want to proceed with deployment? (y/n): " CONFIRM
if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Deployment cancelled.${NC}"
    exit 0
fi

echo -e "${GREEN}Deploying CloudFormation stack...${NC}"

# Build parameters array
PARAMETERS="ParameterKey=Region,ParameterValue=$REGION"
PARAMETERS="$PARAMETERS ParameterKey=VpcId,ParameterValue=$VPC_ID"
PARAMETERS="$PARAMETERS ParameterKey=MainSubnets,ParameterValue=\"$MAIN_SUBNETS\""
PARAMETERS="$PARAMETERS ParameterKey=PodSubnets,ParameterValue=\"$POD_SUBNETS\""
PARAMETERS="$PARAMETERS ParameterKey=HttpsHosts,ParameterValue=\"$HTTPS_HOSTS\""
PARAMETERS="$PARAMETERS ParameterKey=LogLevel,ParameterValue=$LOG_LEVEL"
PARAMETERS="$PARAMETERS ParameterKey=InstanceType,ParameterValue=$INSTANCE_TYPE"

if [ ! -z "$INSTANCE_AMI" ]; then
    PARAMETERS="$PARAMETERS ParameterKey=InstanceAMI,ParameterValue=$INSTANCE_AMI"
fi

if [ ! -z "$API_ENDPOINT" ]; then
    PARAMETERS="$PARAMETERS ParameterKey=ApiEndpoint,ParameterValue=$API_ENDPOINT"
fi

# Deploy the stack
aws cloudformation create-stack \
    --stack-name "$STACK_NAME" \
    --template-body file://$TEMPLATE_PATH \
    --parameters $PARAMETERS \
    --capabilities CAPABILITY_NAMED_IAM \
    --region "$REGION"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Stack creation initiated successfully!${NC}"
    echo "You can monitor the stack creation in the AWS CloudFormation console."
    echo
    echo -e "${YELLOW}Waiting for stack creation to complete...${NC}"
    
    aws cloudformation wait stack-create-complete --stack-name "$STACK_NAME" --region "$REGION"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Stack creation completed successfully!${NC}"
        
        # Get stack outputs
        OUTPUTS=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" --query "Stacks[0].Outputs" --output json)
        
        echo -e "${YELLOW}Stack Outputs:${NC}"
        
        if command -v jq &> /dev/null; then
            echo "$OUTPUTS" | jq -r '.[] | "\(.OutputKey): \(.OutputValue)"'
        else
            echo "$OUTPUTS"
        fi
        
        # Extract instance ID and SSM URL if jq is available
        if command -v jq &> /dev/null; then
            INSTANCE_ID=$(echo "$OUTPUTS" | jq -r '.[] | select(.OutputKey=="InstanceId") | .OutputValue')
            SSM_URL=$(echo "$OUTPUTS" | jq -r '.[] | select(.OutputKey=="SSMSessionURL") | .OutputValue')
            VIEW_LOGS_CMD=$(echo "$OUTPUTS" | jq -r '.[] | select(.OutputKey=="ViewLogsCommand") | .OutputValue')
            
            echo
            echo -e "${GREEN}To view the network check results:${NC}"
            echo "1. Visit the SSM Session URL: $SSM_URL"
            echo "2. Or run this command: $VIEW_LOGS_CMD"
        fi
    else
        echo -e "${RED}Stack creation failed or timed out. Check the AWS CloudFormation console for details.${NC}"
    fi
else
    echo -e "${RED}Failed to initiate stack creation. Check the error message above.${NC}"
fi
