# gitpod-network-check

A CLI to check if your network setup is suitable for the installation of Gitpod.

## How to use

1. In order to perform a network check create a config filed called gitpod-network-check.yaml file that needs to be located in the same directory as the gitpod-network-check binary. Alternatively you can use the `--config` option to specify the config file. The config file needs to contain the region and the subnets that you want to use for your Gitpod installation.

```yaml
log-level: debug # Options: debug, info, warning, error
region: eu-central-1
main-subnets: subnet-0554e84f033a64c56, subnet-08584621e7754e505, subnet-094c6fd68aea493b7
pod-subnets: subnet-028d11dce93b8eefc, subnet-04ec8257d95c434b7,subnet-00a83550ce709f39c
```

2. Get the AWS credentials of the account where you want to install Gitpod and set them as environment variables

3. Run `gitpod-network-check diagnose`. The expected output should look similar to this.

```
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
```
