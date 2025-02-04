# gitpod-network-check

A CLI to check if your network setup is suitable for the installation of Gitpod.

## Prerequisites

1. Download the latest `gitpod-network-check` binary using:
   ```
   curl -s https://api.github.com/repos/gitpod-io/enterprise-deployment-toolkit/releases/latest | \
   grep "browser_download_url.*$(uname -s)_$(uname -m)" | \
   cut -d : -f 2,3 | \
   tr -d \" | \
   xargs curl -L | tar -xz
   ```

   You can also download and untar the binary directly from the Github releases page [here](https://github.com/gitpod-io/enterprise-deployment-toolkit/releases/latest)

   Try running the command with help flag, to see if it downloaded properly:
   ```
   ./gitpod-network-check --help
   ```

2. Set up AWS credentials

   `gitpod-network-check` needs access to the AWS account you are planning to use to deploy Gitpod in. Much like AWS CLI, `gitpod-network-check` uses the available AWS profile in your terminal to authenticate against the account. This means that you can rely on any locally available [AWS profiles](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html) or just set the right environment variables in your terminal for the CLI to use:
   ```
   export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
   export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
   export AWS_SESSION_TOKEN=AQoDYXdzEJr...<remainder of security token>
   export AWS_REGION=eu-central-1 # Replace with the region you want to use
   ```

## Usage

1. Preparation

   To run a diagnosis of the network that you want to use for Gitpod, the CLI command needs to know the subnets you have chosen to be used as the `Main` subnets and the `Pod` subnets. You can read more about the distinction here in [our docs](https://www.gitpod.io/docs/enterprise/getting-started/networking#2-subnet-separation). The CLI expects to read the IDs of these subnets in a configuration file. By default it tries to read it from a file name `gitpod-network-check.yaml` in your current directory, but you can override this behavior by using the `--config` flag of the CLI.

   For the sake of simplicity, let us create a file `gitpod-network-check.yaml` in the current directory and populate it with the subnet IDs and AWS region as shown below:
   ```yaml
   log-level: debug # Options: debug, info, warning, error
   region: eu-central-1
   main-subnets: subnet-0554e84f033a64c56, subnet-08584621e7754e505, subnet-094c6fd68aea493b7
   pod-subnets: subnet-028d11dce93b8eefc, subnet-04ec8257d95c434b7,subnet-00a83550ce709f39c
   https-hosts: accounts.google.com, github.com
   instance-ami: # put your custom ami id here if you want to use it, otherwise it will using latest ubuntu AMI from aws
   api-endpoint: # optional, put your API endpoint regional sub-domain here to test connectivity, like when the execute-api vpc endpoint is not in the same account as Gitpod 
   ```

   note: if using a custom AMI, please ensure the [SSM agent](https://docs.aws.amazon.com/systems-manager/latest/userguide/manually-install-ssm-agent-linux.html) and [curl](https://curl.se/) are both installed. We rely on SSM's [SendCommand](https://docs.aws.amazon.com/code-library/latest/ug/ssm_example_ssm_SendCommand_section.html) to test HTTPS connectivity.

2. Run the network diagnosis

   To start the diagnosis, the the command: `./gitpod-network-check diagnose`

   ```console
   ./gitpod-network-check diagnose
   INFO[0000] ✅ Main Subnets are valid
   INFO[0000] ✅ Pod Subnets are valid
   INFO[0000] ℹ️  Checking prerequisites
   INFO[0000] ✅ VPC endpoint com.amazonaws.eu-central-1.ec2messages is configured
   INFO[0000] ✅ VPC endpoint com.amazonaws.eu-central-1.ssm is configured
   INFO[0000] ✅ VPC endpoint com.amazonaws.eu-central-1.ssmmessages is configured
   INFO[0001] ℹ️  Launching EC2 instance in a Main subnet
   INFO[0007] ℹ️  Launching EC2 instance in a Pod subnet
   INFO[0009] ℹ️  Waiting for EC2 instances to become ready (can take up to 2 minutes)
   INFO[0167] ✅ EC2 Instances are now running successfully
   INFO[0167] ℹ️  Connecting to SSM...
   INFO[0175] ℹ️  Checking if the required AWS Services can be reached from the ec2 instances
   INFO[0178] ✅ Autoscaling is available
   INFO[0179] ✅ CloudFormation is available
   INFO[0179] ✅ CloudWatch is available
   INFO[0180] ✅ EC2 is available
   INFO[0181] ✅ EC2messages is available
   INFO[0182] ✅ ECR is available
   INFO[0183] ✅ ECR Api is available
   INFO[0184] ✅ EKS is available
   INFO[0185] ✅ Elastic LoadBalancing is available
   INFO[0185] ✅ KMS is available
   INFO[0186] ✅ Kinesis Firehose is available
   INFO[0187] ✅ SSM is available
   INFO[0188] ✅ SSMmessages is available
   INFO[0189] ✅ SecretsManager is available
   INFO[0190] ✅ Sts is available
   INFO[0190] ✅ DynamoDB is available
   INFO[0191] ✅ S3 is available
   INFO[0194] ✅ accounts.google.com is available
   INFO[0194] ✅ github.com is available
   INFO[0194] ✅ Instances terminated
   ```

3. Clean up after network diagnosis

   Dianosis is designed to do clean-up before it finishes. However, if the process terminates unexpectedly, you may clean-up AWS resources it creates like so:

   ```console
   ./gitpod-network-check clean
   INFO[0000] ✅ Main Subnets are valid
   INFO[0000] ✅ Pod Subnets are valid
   INFO[0000] ✅ Instances terminated
   INFO[0000] Cleaning up: Waiting for 2 minutes so network interfaces are deleted
   INFO[0121] ✅ Role 'GitpodNetworkCheck' deleted
   INFO[0121] ✅ Instance profile deleted
   INFO[0122] ✅ Security group 'sg-0a6119dcb6a564fc1' deleted
   INFO[0122] ✅ Security group 'sg-07373362953212e54' deleted
   ```

## FAQ

If the EC2 instances are timing out, or you cannot connect to them with Session Manager, be sure to add the following policies.

For the ssm vpc endpoint, add the following policy:

```json
{
   "Effect": "Allow",
   "Action": [
      "*"
   ],
   "Resource": [
      "*"
   ],
   "Principal": {
      "AWS": [
         "*"
      ]
   },
   "Condition": {
      "ArnEquals": {
         "aws:PrincipalArn": "arn:aws:iam::<aws-account-id>:role/GitpodNetworkCheck"
      }
   }
},
{
   "Effect": "Allow",
   "Action": [
      "*"
   ],
   "Resource": [
      "*"
   ],
   "Principal": {
      "AWS": [
         "*"
      ]
   },
   "Condition": {
      "StringEquals": {
         "ec2:InstanceProfile": "arn:aws:iam::<aws-account-id>:instance-profile/GitpodNetworkCheck"
      }
   }
}
```

For the ec2messages and ssmmessages vpc endpoints, add the following policy:

```json
{
   "Effect": "Allow",
   "Action": [
      "*"
   ],
   "Resource": [
      "*"
   ],
   "Principal": {
      "AWS": [
         "*"
      ]
   },
   "Condition": {
      "ArnEquals": {
         "aws:PrincipalArn": "arn:aws:iam::<aws-account-id>:role/GitpodNetworkCheck"
      }
   }
}
```
