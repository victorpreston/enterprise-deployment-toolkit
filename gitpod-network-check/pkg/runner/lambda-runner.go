package runner

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url" // Added for decoding policy document
	"os"
	"path/filepath"
	"strings" // Added import for string manipulation
	"sync"    // Added for mutex
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"                // Added import for log group cleanup
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types" // Added import for log group cleanup types
	"github.com/aws/aws-sdk-go-v2/service/ec2"                           // Added import
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"            // Added import with alias
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types" // Added import with alias
	smithy "github.com/aws/smithy-go"                               // Added import for API error handling
	"golang.org/x/sync/errgroup"                                    // Added for parallel execution

	log "github.com/sirupsen/logrus"

	"github.com/gitpod-io/enterprise-deployment-toolkit/gitpod-network-check/pkg/checks"
	"github.com/gitpod-io/enterprise-deployment-toolkit/gitpod-network-check/pkg/lambda_types" // Import shared types
)

// LambdaTestRunner implements the TestRunner interface using AWS Lambda.
type LambdaTestRunner struct {
	awsConfig            aws.Config
	lambdaClient         *lambda.Client
	iamClient            *iam.Client
	ec2Client            *ec2.Client            // Added EC2 client
	cloudwatchlogsClient *cloudwatchlogs.Client // Added CloudWatch Logs client
	config               *checks.NetworkConfig

	// State managed by Prepare/Cleanup
	roleArn         *string
	securityGroupID *string
	functionArns    map[string]string // Map subnetID -> function ARN
	funcMapMutex    sync.Mutex        // Mutex to protect functionArns map
	codeZipPath     string
	runID           string // Unique ID for this run, used for tagging
	tags            map[string]string
}

const (
	lambdaFunctionNamePrefix = "gitpod-network-check-"
	lambdaRoleName           = "GitpodNetworkCheckLambdaRole"
	inlinePolicyName         = "GitpodNetworkCheckServiceAccessPolicy"
	lambdaSecurityGroupName  = "gitpod-network-check-lambda-sg"
)

// NewLambdaTestRunner creates a new LambdaTestRunner.
func NewLambdaTestRunner(ctx context.Context, config *checks.NetworkConfig) (*LambdaTestRunner, error) {
	log.Info("Initializing Lambda test runner...")
	awsCfg, err := initAwsConfig(ctx, config.AwsRegion)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return &LambdaTestRunner{
		awsConfig:            awsCfg,
		lambdaClient:         lambda.NewFromConfig(awsCfg),
		iamClient:            iam.NewFromConfig(awsCfg),
		ec2Client:            ec2.NewFromConfig(awsCfg),            // Initialize EC2 client
		cloudwatchlogsClient: cloudwatchlogs.NewFromConfig(awsCfg), // Initialize CloudWatch Logs client
		config:               config,
		functionArns:         make(map[string]string),
		runID:                fmt.Sprintf("%d", time.Now().Unix()), // Use seconds for shorter runID
		tags:                 NetworkCheckTags,
	}, nil
}

// Prepare sets up the necessary AWS resources (IAM role, Security Group, Lambda functions).
// It returns an error if any step fails, relying on the caller to invoke Cleanup.
func (r *LambdaTestRunner) Prepare(ctx context.Context) (err error) { // Named return err for easier deferred cleanup
	log.Info("Lambda Runner: Prepare phase starting...")
	var createdRole bool
	var createdSG bool

	// Note: Cleanup on error is now handled by the caller invoking the Cleanup method.
	// The named return 'err' ensures that any error encountered below is returned.

	// 1. Get or Create IAM Role
	roleArn, createdRole, err := r.getOrCreateLambdaRole(ctx) // Modified to return creation status
	if err != nil {
		return fmt.Errorf("failed to get or create IAM role: %w", err) // Error is captured by named return
	}
	r.roleArn = roleArn
	log.Infof("✅ Using IAM Role ARN: %s (Created: %t)", *r.roleArn, createdRole)

	// 2. Package Lambda Code
	var zipPath string
	zipPath, err = r.packageLambdaCode(ctx)
	if err != nil {
		return fmt.Errorf("failed to package lambda code: %w", err) // Error captured by named return
	}
	r.codeZipPath = zipPath
	log.Infof("✅ Packaged Lambda code to: %s", r.codeZipPath)
	// Defer cleanup of the zip file
	defer func() {
		if r.codeZipPath != "" {
			log.Debugf("Removing temporary zip file: %s", r.codeZipPath)
			_ = os.Remove(r.codeZipPath) // Best effort removal
		}
	}()

	// 3. Get or Create Security Group
	// We need the VPC ID first. Assume all subnets are in the same VPC.
	var vpcID *string
	vpcID, err = r.getVpcIDFromSubnets(ctx)
	if err != nil {
		return fmt.Errorf("failed to determine VPC ID from subnets: %w", err) // Error captured by named return
	}
	var sgID *string
	sgID, createdSG, err = r.getOrCreateSecurityGroup(ctx, vpcID) // Modified to return creation status
	if err != nil {
		return fmt.Errorf("failed to get or create security group: %w", err) // Error captured by named return
	}
	r.securityGroupID = sgID
	log.Infof("✅ Using Security Group ID: %s (Created: %t)", *r.securityGroupID, createdSG)

	// 4. Deploy Lambda Function(s)
	log.Info("Deploying Lambda functions...")
	targetSubnets := r.config.GetAllSubnets() // Get all configured subnets
	if len(targetSubnets) == 0 {
		err = fmt.Errorf("no subnets configured for Lambda deployment") // Assign to named return
		return err
	}

	var zipContent []byte
	zipContent, err = os.ReadFile(r.codeZipPath)
	if err != nil {
		err = fmt.Errorf("failed to read packaged lambda code zip %s: %w", r.codeZipPath, err) // Assign to named return
		return err
	}

	// Deploy one function per unique subnet ID in parallel
	var eg errgroup.Group
	uniqueSubnets := make(map[string]checks.Subnet) // Store unique cleaned subnet IDs and original struct

	log.Debugf("Identifying unique subnets for deployment...")
	for _, subnet := range r.config.GetAllSubnets() {
		// More robust cleaning: extract only valid subnet characters
		var sb strings.Builder
		for _, r := range subnet.SubnetID {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				sb.WriteRune(r)
			}
		}
		cleanSubnetID := sb.String()

		// Basic validation after cleaning
		if !strings.HasPrefix(cleanSubnetID, "subnet-") || len(cleanSubnetID) < 8 { // Basic sanity check
			log.Warnf("Invalid subnet ID format after cleaning: '%s' (Original: '%s'). Skipping.", cleanSubnetID, subnet.SubnetID)
			// Don't immediately return error, just skip this one
			continue
		}

		if _, exists := uniqueSubnets[cleanSubnetID]; !exists {
			log.Debugf("Adding unique subnet %s to deployment list (Original: %s)", cleanSubnetID, subnet.SubnetID)
			uniqueSubnets[cleanSubnetID] = subnet // Store original struct with cleaned ID as key
		} else {
			log.Debugf("Subnet %s already in deployment list (Original: %s)", cleanSubnetID, subnet.SubnetID)
		}
	}

	if len(uniqueSubnets) == 0 {
		// This might happen if all input subnet IDs were invalid after cleaning
		return fmt.Errorf("no valid subnets found to deploy Lambda functions into after cleaning input")
	}

	log.Infof("Starting parallel deployment for %d unique subnets...", len(uniqueSubnets))

	for cleanSubnetID := range uniqueSubnets {
		// Capture loop variable for goroutine
		currentCleanSubnetID := cleanSubnetID

		eg.Go(func() error {
			functionName := fmt.Sprintf("%s%s-%s", lambdaFunctionNamePrefix, currentCleanSubnetID, r.runID)
			// Check function name length again
			if len(functionName) > 64 {
				log.Errorf("❌ Generated function name '%s' is too long (%d chars > 64) for subnet ID '%s'. Skipping.", functionName, len(functionName), currentCleanSubnetID)
				// Return error from goroutine
				return fmt.Errorf("generated function name too long: %s", functionName)
			}

			log.Infof("Deploying Lambda function '%s' for subnet %s", functionName, currentCleanSubnetID)

			createInput := &lambda.CreateFunctionInput{
				FunctionName: aws.String(functionName),
				Role:         r.roleArn,
				Code:         &lambdatypes.FunctionCode{ZipFile: zipContent},
				Handler:      aws.String("bootstrap"),        // The name of our script
				Runtime:      lambdatypes.RuntimeProvidedal2, // Use the provided runtime
				Description:  aws.String(fmt.Sprintf("Gitpod Network Check function for subnet %s (RunID: %s)", cleanSubnetID, r.runID)),
				Timeout:      aws.Int32(30),  // 30 seconds timeout, adjust as needed
				MemorySize:   aws.Int32(256), // Minimum memory size
				Publish:      true,           // Publish the first version
				VpcConfig: &lambdatypes.VpcConfig{
					SubnetIds:        []string{currentCleanSubnetID}, // Use captured loop variable
					SecurityGroupIds: []string{*r.securityGroupID},
				},
				Tags: NetworkCheckTags, // Use exported var
				// Architectures field might not be needed for provided.al2, but keeping x86_64 is safe.
				Architectures: []lambdatypes.Architecture{lambdatypes.ArchitectureX8664},
			}

			var createOutput *lambda.CreateFunctionOutput
			createOutput, err = r.lambdaClient.CreateFunction(ctx, createInput)
			if err != nil {
				// Use currentCleanSubnetID in error message
				return fmt.Errorf("failed to create lambda function %s for subnet %s: %w", functionName, currentCleanSubnetID, err)
			}
			log.Infof("Lambda function %s created with ARN: %s. Waiting for it to become active...", functionName, *createOutput.FunctionArn)

			// Wait for the function to become active (moved to helper)
			waitErr := r.waitForLambdaActive(ctx, createOutput.FunctionArn)
			if waitErr != nil {
				log.Errorf("❌ Error waiting for Lambda function %s (Subnet: %s) to become active: %v", *createOutput.FunctionArn, currentCleanSubnetID, waitErr)
				// Return error from goroutine
				return fmt.Errorf("error waiting for lambda %s to become active: %w", *createOutput.FunctionArn, waitErr)
			}

			// Store the ARN safely
			r.funcMapMutex.Lock()
			r.functionArns[currentCleanSubnetID] = *createOutput.FunctionArn // Use cleaned subnet ID as map key
			r.funcMapMutex.Unlock()

			return nil // Goroutine finished successfully
		})
	}

	// Wait for all goroutines to finish and collect the first error
	if err = eg.Wait(); err != nil {
		return fmt.Errorf("one or more errors occurred during parallel Lambda deployment: %w", err)
	}

	log.Info("Lambda Runner: Prepare phase completed successfully.")
	return nil
}

// waitForLambdaActive polls the Lambda function until it becomes active or times out.
func (r *LambdaTestRunner) waitForLambdaActive(ctx context.Context, functionArn *string) error {
	const maxWaitTime = 2 * time.Minute // Reduced timeout slightly as multiple waits run in parallel
	const pollInterval = 5 * time.Second
	startTime := time.Now()

	for {
		getFuncInput := &lambda.GetFunctionInput{
			FunctionName: functionArn,
		}
		getFuncOutput, err := r.lambdaClient.GetFunction(ctx, getFuncInput)
		if err != nil {
			// If the function is not found immediately after creation, it might be an eventual consistency issue. Retry.
			log.Warnf("Error getting function %s status (will retry): %v", *functionArn, err)
		} else if getFuncOutput.Configuration != nil && getFuncOutput.Configuration.State == lambdatypes.StateActive {
			log.Infof("✅ Lambda function %s is now active.", *functionArn)
			return nil // Function is active
		} else if getFuncOutput.Configuration != nil && (getFuncOutput.Configuration.State == lambdatypes.StateFailed || getFuncOutput.Configuration.State == lambdatypes.StateInactive) {
			// Handle terminal failure states
			stateReason := "Unknown reason"
			if getFuncOutput.Configuration.StateReason != nil {
				stateReason = *getFuncOutput.Configuration.StateReason
			}
			log.Errorf("❌ Lambda function %s entered terminal state %s (%s).", *functionArn, getFuncOutput.Configuration.State, stateReason)
			return fmt.Errorf("lambda function %s failed to become active, entered state %s: %s", *functionArn, getFuncOutput.Configuration.State, stateReason)
		} else {
			// Still pending or other state, continue waiting
			currentState := "Unknown"
			if getFuncOutput.Configuration != nil && getFuncOutput.Configuration.State != "" {
				currentState = string(getFuncOutput.Configuration.State)
			}
			log.Infof("Lambda function %s state is %s, waiting...", *functionArn, currentState)
		}

		if time.Since(startTime) > maxWaitTime {
			log.Errorf("❌ Timed out waiting for Lambda function %s to become active after %v.", *functionArn, maxWaitTime)
			return fmt.Errorf("timed out waiting for lambda function %s to become active", *functionArn)
		}

		// Check context cancellation
		select {
		case <-ctx.Done():
			log.Warnf("Context cancelled while waiting for Lambda function %s to become active.", *functionArn)
			return ctx.Err()
		case <-time.After(pollInterval):
			// Continue loop
		}
	}
}

// packageLambdaCode finds the current executable, creates a bootstrap script, and zips them.
func (r *LambdaTestRunner) packageLambdaCode(ctx context.Context) (string, error) {
	zipFileName := fmt.Sprintf("lambda-gpnwc-%s.zip", r.runID)
	bootstrapScriptName := "bootstrap"
	executableName := "gitpod-network-check" // Name of the binary inside the zip

	// Find the path of the currently running executable
	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get current executable path: %w", err)
	}
	log.Infof("Using current executable for Lambda package: %s", exePath)

	// Create a temporary directory for staging files
	tempDir, err := os.MkdirTemp("", "lambda-pkg-")
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir for packaging: %w", err)
	}
	defer os.RemoveAll(tempDir) // Clean up temp dir afterwards
	log.Debugf("Created temporary staging directory: %s", tempDir)

	// Define bootstrap script content
	bootstrapContent := fmt.Sprintf(`#!/bin/sh
set -e
echo "Bootstrap: Running %s lambda-handler" >&2
./%s lambda-handler
`, executableName, executableName)

	// Write bootstrap script to temp dir
	bootstrapPath := filepath.Join(tempDir, bootstrapScriptName)
	err = os.WriteFile(bootstrapPath, []byte(bootstrapContent), 0755) // rwxr-xr-x permissions
	if err != nil {
		return "", fmt.Errorf("failed to write bootstrap script %s: %w", bootstrapPath, err)
	}
	log.Infof("Created bootstrap script: %s", bootstrapPath)

	// Copy executable to temp dir with the target name
	destExePath := filepath.Join(tempDir, executableName)
	log.Debugf("Copying executable from %s to %s", exePath, destExePath)
	sourceFile, err := os.Open(exePath)
	if err != nil {
		return "", fmt.Errorf("failed to open source executable %s: %w", exePath, err)
	}
	defer sourceFile.Close()

	destFile, err := os.OpenFile(destExePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755) // rwxr-xr-x
	if err != nil {
		return "", fmt.Errorf("failed to create destination executable %s: %w", destExePath, err)
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return "", fmt.Errorf("failed to copy executable: %w", err)
	}
	log.Infof("Copied executable to: %s", destExePath)

	// Create the zip archive
	finalZipPath := filepath.Join(".", zipFileName) // Place final zip in CWD
	log.Infof("Creating zip archive: %s", finalZipPath)
	zipFile, err := os.Create(finalZipPath)
	if err != nil {
		return "", fmt.Errorf("failed to create zip file %s: %w", finalZipPath, err)
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// Add files from tempDir to zip
	filesToZip := []string{bootstrapScriptName, executableName}
	for _, filename := range filesToZip {
		filePath := filepath.Join(tempDir, filename)
		log.Debugf("Adding %s to zip archive", filePath)

		fileToZip, err := os.Open(filePath)
		if err != nil {
			return "", fmt.Errorf("failed to open file %s for zipping: %w", filePath, err)
		}
		defer fileToZip.Close()

		info, err := fileToZip.Stat()
		if err != nil {
			return "", fmt.Errorf("failed to stat file %s: %w", filePath, err)
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return "", fmt.Errorf("failed to create zip header for %s: %w", filename, err)
		}
		// Use base name (filename) in zip archive's root
		header.Name = filename
		header.Method = zip.Deflate // Use compression

		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			return "", fmt.Errorf("failed to create zip writer for %s: %w", filename, err)
		}

		_, err = io.Copy(writer, fileToZip)
		if err != nil {
			return "", fmt.Errorf("failed to copy file %s to zip: %w", filename, err)
		}
	}

	log.Info("Lambda code zipped successfully.")
	return finalZipPath, nil
}

// getOrCreateLambdaRole finds or creates the necessary IAM role for the Lambda function,
// respecting the LambdaRoleArn config if provided.
// Returns the Role ARN, a boolean indicating if the role was created in this call, and an error.
func (r *LambdaTestRunner) getOrCreateLambdaRole(ctx context.Context) (*string, bool, error) {
	// Check if a specific Role ARN is provided in the config
	if r.config.LambdaRoleArn != "" {
		roleArnString := r.config.LambdaRoleArn
		log.Infof("Using pre-configured Lambda IAM Role ARN: %s", roleArnString)
		// Extract role name from ARN for GetRole/UpdateAssumeRolePolicy calls
		arnParts := strings.Split(roleArnString, "/")
		if len(arnParts) < 2 {
			return nil, false, fmt.Errorf("invalid pre-configured role ARN format: %s", roleArnString)
		}
		roleName := arnParts[len(arnParts)-1]
		log.Debugf("Extracted role name from provided ARN: %s", roleName)

		// Validate the role exists and check/update its trust policy
		getRoleInput := &iam.GetRoleInput{RoleName: aws.String(roleName)}
		getRoleOutput, err := r.iamClient.GetRole(ctx, getRoleInput)
		if err != nil {
			var nsee *types.NoSuchEntityException
			if errors.As(err, &nsee) {
				return nil, false, fmt.Errorf("pre-configured IAM role %s (ARN: %s) not found: %w", roleName, roleArnString, err)
			}
			return nil, false, fmt.Errorf("failed to get pre-configured IAM role %s: %w", roleName, err)
		}

		// Check and potentially update the trust policy
		policyUpdated, err := r.ensureLambdaTrustPolicy(ctx, getRoleOutput.Role)
		if err != nil {
			return nil, false, fmt.Errorf("failed to ensure trust policy for pre-configured role %s: %w", roleName, err)
		}
		if policyUpdated {
			log.Infof("Updated trust policy for pre-configured role %s. Adding delay for propagation...", roleName)
			time.Sleep(10 * time.Second) // Delay after updating policy
		}

		return aws.String(roleArnString), false, nil // Not created by us, but possibly updated
	}

	// No specific ARN provided, proceed with get-or-create logic for the managed role
	roleName := lambdaRoleName // Assign to existing variable, not redeclare
	log.Infof("Checking for managed IAM role: %s", roleName)

	// Try to get the role first
	getRoleInput := &iam.GetRoleInput{
		RoleName: aws.String(roleName),
	}
	getRoleOutput, err := r.iamClient.GetRole(ctx, getRoleInput)
	if err == nil {
		roleArn := getRoleOutput.Role.Arn
		log.Infof("Found existing managed IAM role: %s", *roleArn)

		// Check and potentially update the trust policy for the existing managed role
		policyUpdated, updateErr := r.ensureLambdaTrustPolicy(ctx, getRoleOutput.Role)
		if updateErr != nil {
			// Log error but don't fail, maybe it's usable anyway? Or maybe permissions issue.
			log.WithError(updateErr).Warnf("Failed to ensure trust policy for existing managed role %s. Proceeding cautiously.", roleName)
		} else if policyUpdated {
			log.Infof("Updated trust policy for existing managed role %s. Adding delay for propagation...", roleName)
			time.Sleep(10 * time.Second) // Delay after updating policy
		}

		// TODO: Optionally verify/update tags or policies on existing role?
		return roleArn, false, nil // Found, not created now, but possibly updated
	}

	// Handle specific error: NoSuchEntityException means we need to create it
	var nsee *types.NoSuchEntityException
	if !errors.As(err, &nsee) {
		return nil, false, fmt.Errorf("failed to get IAM role %s: %w", roleName, err)
	}

	// Role doesn't exist, create it
	log.Infof("IAM role %s not found, creating...", roleName)

	assumeRolePolicy := map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []map[string]interface{}{
			{
				"Effect": "Allow",
				"Principal": map[string]string{
					"Service": "lambda.amazonaws.com",
				},
				"Action": "sts:AssumeRole",
			},
		},
	}
	assumeRolePolicyBytes, _ := json.Marshal(assumeRolePolicy) // Error handling omitted for brevity

	createRoleInput := &iam.CreateRoleInput{
		RoleName:                 aws.String(roleName),
		AssumeRolePolicyDocument: aws.String(string(assumeRolePolicyBytes)),
		Description:              aws.String("Role for Gitpod Network Check Lambda functions"),
		Tags:                     NetworkCheckIamTags,
	}

	createRoleOutput, err := r.iamClient.CreateRole(ctx, createRoleInput)
	if err != nil {
		return nil, false, fmt.Errorf("failed to create IAM role %s: %w", roleName, err)
	}
	log.Infof("Created IAM role: %s", *createRoleOutput.Role.Arn)

	// Attach required managed policies
	policies := []string{
		"arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
		"arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole",
		"arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
	}
	for _, policyArn := range policies {
		log.Infof("Attaching policy %s to role %s", policyArn, roleName)
		attachPolicyInput := &iam.AttachRolePolicyInput{
			RoleName:  aws.String(roleName),
			PolicyArn: aws.String(policyArn),
		}
		_, err := r.iamClient.AttachRolePolicy(ctx, attachPolicyInput)
		if err != nil {
			// Don't attempt cleanup here, caller invoking Cleanup() is responsible
			log.Warnf("Failed to attach policy %s: %v. Role %s might be left in an incomplete state.", policyArn, err, roleName)
			return nil, true, fmt.Errorf("failed to attach policy %s to role %s: %w", policyArn, roleName, err) // Created but failed config
		}
	}

	// Attach the custom inline policy for service access
	inlinePolicyDocument := fmt.Sprintf(`{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Action": [
					"ssm:DescribeParameters"
				],
				"Resource": "*",
				"Effect": "Allow"
			},
			{
				"Action": [
					"ssm:GetParameter",
					"ssm:GetParametersByPath"
				],
				"Resource": "arn:aws:ssm:%s:redacted:parameter/*",
				"Effect": "Allow"
			},
			{
				"Effect": "Allow",
				"Action": [
					"ecr:GetAuthorizationToken",
					"kms:ListKeys",
					"secretsmanager:ListSecrets",
					"logs:DescribeLogGroups",
					"eks:ListClusters",
					"elasticloadbalancing:DescribeLoadBalancers",
					"ec2:DescribeRegions",
					"execute-api:Invoke"
				],
				"Resource": "*"
			}
		]
	}`, r.config.AwsRegion)
	log.Infof("Attaching inline policy %s to role %s", inlinePolicyName, roleName)
	putPolicyInput := &iam.PutRolePolicyInput{
		RoleName:       aws.String(roleName),
		PolicyName:     aws.String(inlinePolicyName),
		PolicyDocument: aws.String(inlinePolicyDocument),
	}
	_, err = r.iamClient.PutRolePolicy(ctx, putPolicyInput)
	if err != nil {
		log.Warnf("Failed to attach inline policy %s: %v. Role %s might be left in an incomplete state.", inlinePolicyName, err, roleName)
		// Don't attempt cleanup here, caller invoking Cleanup() is responsible
		return nil, true, fmt.Errorf("failed to attach inline policy %s to role %s: %w", inlinePolicyName, roleName, err) // Created but failed config
	}

	log.Infof("Successfully created and configured IAM role %s", roleName)

	// Add delay after creating role for IAM propagation
	log.Info("Adding delay after IAM role creation for propagation...")
	time.Sleep(10 * time.Second)

	return createRoleOutput.Role.Arn, true, nil // Created successfully
}

// ensureLambdaTrustPolicy checks if the role's trust policy allows lambda.amazonaws.com
// and updates it if necessary. Returns true if the policy was updated.
func (r *LambdaTestRunner) ensureLambdaTrustPolicy(ctx context.Context, role *types.Role) (bool, error) {
	if role == nil || role.AssumeRolePolicyDocument == nil {
		return false, fmt.Errorf("role or AssumeRolePolicyDocument is nil")
	}

	// AWS policy documents are URL encoded
	decodedPolicy, err := url.QueryUnescape(*role.AssumeRolePolicyDocument)
	if err != nil {
		return false, fmt.Errorf("failed to decode assume role policy document: %w", err)
	}

	var policyDoc map[string]interface{}
	err = json.Unmarshal([]byte(decodedPolicy), &policyDoc)
	if err != nil {
		return false, fmt.Errorf("failed to unmarshal assume role policy document: %w", err)
	}

	statements, ok := policyDoc["Statement"].([]interface{})
	if !ok {
		return false, fmt.Errorf("invalid policy document structure: 'Statement' is not an array")
	}

	lambdaPrincipalFound := false
	for _, stmtInterface := range statements {
		stmt, ok := stmtInterface.(map[string]interface{})
		if !ok {
			continue // Skip invalid statements
		}

		// Check Effect is Allow
		if effect, ok := stmt["Effect"].(string); !ok || effect != "Allow" {
			continue
		}

		// Check Action contains sts:AssumeRole
		actionFound := false
		switch action := stmt["Action"].(type) {
		case string:
			if action == "sts:AssumeRole" || action == "*" {
				actionFound = true
			}
		case []interface{}:
			for _, act := range action {
				if actStr, ok := act.(string); ok && (actStr == "sts:AssumeRole" || actStr == "*") {
					actionFound = true
					break
				}
			}
		}
		if !actionFound {
			continue
		}

		// Check Principal contains lambda.amazonaws.com
		principal, ok := stmt["Principal"].(map[string]interface{})
		if !ok {
			continue
		}
		service, ok := principal["Service"]
		if !ok {
			continue
		}

		switch srv := service.(type) {
		case string:
			if srv == "lambda.amazonaws.com" {
				lambdaPrincipalFound = true
				break // Found it in this statement
			}
		case []interface{}:
			for _, s := range srv {
				if sStr, ok := s.(string); ok && sStr == "lambda.amazonaws.com" {
					lambdaPrincipalFound = true
					break // Found it in the list
				}
			}
		}
		if lambdaPrincipalFound {
			break // Found it in the statements array
		}
	}

	if lambdaPrincipalFound {
		log.Debugf("Role %s already has lambda.amazonaws.com in its trust policy.", *role.RoleName)
		return false, nil // Already has the correct trust policy
	}

	// Lambda principal not found, need to update the policy
	log.Warnf("Role %s is missing 'lambda.amazonaws.com' in its trust policy. Attempting to update.", *role.RoleName)

	// Construct the new policy document - simplest approach is to overwrite with the standard one
	// A more robust approach would merge, but this is likely sufficient for this tool's managed role.
	newAssumeRolePolicy := map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []map[string]interface{}{
			{
				"Effect": "Allow",
				"Principal": map[string]string{
					"Service": "lambda.amazonaws.com",
				},
				"Action": "sts:AssumeRole",
			},
			// Add other principals if they existed? For now, just ensure Lambda is there.
			// If the original policy had other services, this will remove them.
			// Consider fetching, merging, and then updating if preserving others is critical.
		},
	}
	newAssumeRolePolicyBytes, _ := json.Marshal(newAssumeRolePolicy)

	updateInput := &iam.UpdateAssumeRolePolicyInput{
		RoleName:       role.RoleName,
		PolicyDocument: aws.String(string(newAssumeRolePolicyBytes)),
	}

	_, err = r.iamClient.UpdateAssumeRolePolicy(ctx, updateInput)
	if err != nil {
		return false, fmt.Errorf("failed to update assume role policy for role %s: %w", *role.RoleName, err)
	}

	log.Infof("Successfully updated trust policy for role %s to include lambda.amazonaws.com.", *role.RoleName)
	return true, nil // Policy was updated
}

// getVpcIDFromSubnets determines the VPC ID from the configured subnets.
// Assumes all subnets belong to the same VPC.
func (r *LambdaTestRunner) getVpcIDFromSubnets(ctx context.Context) (*string, error) {
	allSubnetIDs := r.config.GetAllSubnets()
	if len(allSubnetIDs) == 0 {
		return nil, fmt.Errorf("no subnets configured, cannot determine VPC ID")
	}

	// Describe the first subnet to get the VPC ID
	firstSubnetID := allSubnetIDs[0].SubnetID
	describeInput := &ec2.DescribeSubnetsInput{
		SubnetIds: []string{firstSubnetID},
	}
	describeOutput, err := r.ec2Client.DescribeSubnets(ctx, describeInput)
	if err != nil {
		return nil, fmt.Errorf("failed to describe subnet %s: %w", firstSubnetID, err)
	}
	if len(describeOutput.Subnets) == 0 {
		return nil, fmt.Errorf("subnet %s not found", firstSubnetID)
	}
	vpcID := describeOutput.Subnets[0].VpcId
	log.Debugf("Determined VPC ID: %s from subnet %s", *vpcID, firstSubnetID)
	return vpcID, nil
}

// getOrCreateSecurityGroup finds or creates the necessary Security Group for the Lambda function,
// respecting the LambdaSecurityGroupID config if provided.
// Returns the SG ID, a boolean indicating if the SG was created in this call, and an error.
func (r *LambdaTestRunner) getOrCreateSecurityGroup(ctx context.Context, vpcID *string) (*string, bool, error) {
	// Check if a specific Security Group ID is provided in the config
	if r.config.LambdaSecurityGroupID != "" {
		log.Infof("Using pre-configured Lambda Security Group ID: %s", r.config.LambdaSecurityGroupID)
		// Optionally, perform a DescribeSecurityGroups call to validate the ID exists and is accessible?
		// For now, assume the provided ID is valid.
		return aws.String(r.config.LambdaSecurityGroupID), false, nil // Not created by us
	}

	// No specific SG ID provided, proceed with get-or-create logic
	sgName := lambdaSecurityGroupName
	log.Infof("Checking for managed Security Group: %s in VPC %s", sgName, *vpcID)

	// Try to find the SG by name and tag
	describeInput := &ec2.DescribeSecurityGroupsInput{
		Filters: append(NetworkCheckTagsFilter,
			ec2types.Filter{Name: aws.String("vpc-id"), Values: []string{*vpcID}},
			ec2types.Filter{Name: aws.String("group-name"), Values: []string{sgName}},
		),
	}

	describeOutput, err := r.ec2Client.DescribeSecurityGroups(ctx, describeInput)
	if err != nil {
		// Handle potential AWS errors if needed, otherwise assume it doesn't exist or other issue
		log.Warnf("Could not describe security groups (maybe transient error or SG doesn't exist): %v", err)
	}

	if describeOutput != nil && len(describeOutput.SecurityGroups) > 0 {
		// Found existing managed SG
		sgID := describeOutput.SecurityGroups[0].GroupId
		log.Infof("Found existing managed Security Group: %s", *sgID)
		// Ensure the necessary egress rules exist even if we found the SG
		ipv4Rule := ec2types.IpPermission{
			IpProtocol: aws.String("-1"),
			IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
		}
		if err := ensureSecurityGroupEgressRule(ctx, r.ec2Client, sgID, ipv4Rule); err != nil {
			log.WithError(err).Warnf("Failed to ensure IPv4 egress rule for existing SG %s", *sgID)
			// Continue, but log the warning
		}
		ipv6Rule := ec2types.IpPermission{
			IpProtocol: aws.String("-1"),
			Ipv6Ranges: []ec2types.Ipv6Range{{CidrIpv6: aws.String("::/0")}},
		}
		if err := ensureSecurityGroupEgressRule(ctx, r.ec2Client, sgID, ipv6Rule); err != nil {
			log.WithError(err).Warnf("Failed to ensure IPv6 egress rule for existing SG %s", *sgID)
			// Continue, but log the warning
		}
		return sgID, false, nil // Found, not created now
	}

	// Security Group doesn't exist, create it
	log.Infof("Security Group %s not found, creating...", sgName)

	tagSpec := []ec2types.TagSpecification{
		{ResourceType: ec2types.ResourceTypeSecurityGroup, Tags: NetworkCheckEC2Tags},
	}

	createInput := &ec2.CreateSecurityGroupInput{
		GroupName:         aws.String(sgName),
		Description:       aws.String("Security Group for Gitpod Network Check Lambda"),
		VpcId:             vpcID,
		TagSpecifications: tagSpec,
	}

	createOutput, err := r.ec2Client.CreateSecurityGroup(ctx, createInput)
	if err != nil {
		return nil, false, fmt.Errorf("failed to create security group %s: %w", sgName, err)
	}
	sgID := createOutput.GroupId
	log.Infof("Created Security Group: %s", *sgID)

	// Ensure the necessary egress rules exist after creation
	ipv4Rule := ec2types.IpPermission{
		IpProtocol: aws.String("-1"),
		IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
	}
	if err := ensureSecurityGroupEgressRule(ctx, r.ec2Client, sgID, ipv4Rule); err != nil {
		log.WithError(err).Errorf("Failed to ensure IPv4 egress rule for newly created SG %s", *sgID)
		// Return error as this is critical for a new SG
		return nil, true, fmt.Errorf("failed to ensure IPv4 egress rule for security group %s: %w", *sgID, err) // Created but failed config
	}

	ipv6Rule := ec2types.IpPermission{
		IpProtocol: aws.String("-1"),
		Ipv6Ranges: []ec2types.Ipv6Range{{CidrIpv6: aws.String("::/0")}},
	}
	if err := ensureSecurityGroupEgressRule(ctx, r.ec2Client, sgID, ipv6Rule); err != nil {
		log.WithError(err).Errorf("Failed to ensure IPv6 egress rule for newly created SG %s", *sgID)
		// Return error as this is critical for a new SG
		return nil, true, fmt.Errorf("failed to ensure IPv6 egress rule for security group %s: %w", *sgID, err) // Created but failed config
	}

	log.Infof("Successfully created and configured Security Group %s", *sgID)
	return sgID, true, nil // Created successfully
}

// ensureSecurityGroupEgressRule checks if a specific egress rule exists and adds it if not.
func ensureSecurityGroupEgressRule(ctx context.Context, ec2Client *ec2.Client, sgID *string, rule ec2types.IpPermission) error {
	log.Debugf("Ensuring egress rule for SG %s: Proto=%s, IPv4=%v, IPv6=%v",
		*sgID, aws.ToString(rule.IpProtocol), rule.IpRanges, rule.Ipv6Ranges)

	// Describe the security group to check existing rules
	describeInput := &ec2.DescribeSecurityGroupsInput{
		GroupIds: []string{*sgID},
	}
	describeOutput, err := ec2Client.DescribeSecurityGroups(ctx, describeInput)
	if err != nil {
		// Log warning but don't necessarily fail the whole operation, maybe transient?
		log.WithError(err).Warnf("Could not describe security group %s to check egress rules", *sgID)
		// Proceed with caution - attempt to add the rule anyway? Or return error?
		// Let's return error to be safer, as we can't verify.
		return fmt.Errorf("failed to describe security group %s to verify egress rule: %w", *sgID, err)
	}

	if len(describeOutput.SecurityGroups) == 0 {
		return fmt.Errorf("security group %s not found during egress rule check", *sgID)
	}
	sg := describeOutput.SecurityGroups[0]

	// Check if the rule already exists
	ruleExists := false
	for _, existingRule := range sg.IpPermissionsEgress {
		if aws.ToString(existingRule.IpProtocol) == aws.ToString(rule.IpProtocol) &&
			ipRangesMatch(existingRule.IpRanges, rule.IpRanges) &&
			ipv6RangesMatch(existingRule.Ipv6Ranges, rule.Ipv6Ranges) {
			ruleExists = true
			break
		}
	}

	if ruleExists {
		log.Debugf("Egress rule already exists for SG %s: Proto=%s, IPv4=%v, IPv6=%v",
			*sgID, aws.ToString(rule.IpProtocol), rule.IpRanges, rule.Ipv6Ranges)
		return nil // Rule exists, nothing to do
	}

	// Rule doesn't exist, add it
	log.Infof("Authorizing missing egress rule for SG %s: Proto=%s, IPv4=%v, IPv6=%v",
		*sgID, aws.ToString(rule.IpProtocol), rule.IpRanges, rule.Ipv6Ranges)
	authInput := &ec2.AuthorizeSecurityGroupEgressInput{
		GroupId:       sgID,
		IpPermissions: []ec2types.IpPermission{rule},
	}
	_, err = ec2Client.AuthorizeSecurityGroupEgress(ctx, authInput)
	if err != nil {
		// Check for duplicate error specifically, although the check above should prevent it
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "InvalidPermission.Duplicate" {
			log.Warnf("Attempted to add duplicate egress rule for SG %s despite check (potential race condition?): %v", *sgID, err)
			return nil // Treat as success if it's just a duplicate error
		}
		log.Errorf("Failed to authorize egress rule for SG %s: %v", *sgID, err)
		return fmt.Errorf("failed to authorize egress rule for security group %s: %w", *sgID, err)
	}

	log.Infof("Successfully authorized egress rule for SG %s", *sgID)
	return nil
}

// Helper to compare IP ranges (order doesn't matter)
func ipRangesMatch(a, b []ec2types.IpRange) bool {
	if len(a) != len(b) {
		return false
	}
	mapA := make(map[string]struct{}, len(a))
	for _, r := range a {
		if r.CidrIp != nil {
			mapA[*r.CidrIp] = struct{}{}
		}
	}
	for _, r := range b {
		if r.CidrIp == nil { // If b has a nil entry, it can't match
			return false
		}
		if _, ok := mapA[*r.CidrIp]; !ok {
			return false
		}
	}
	// Ensure the counts match exactly (handles cases where a has duplicates)
	return len(mapA) == len(b)
}

// Helper to compare IPv6 ranges (order doesn't matter)
func ipv6RangesMatch(a, b []ec2types.Ipv6Range) bool {
	if len(a) != len(b) {
		return false
	}
	mapA := make(map[string]struct{}, len(a))
	for _, r := range a {
		if r.CidrIpv6 != nil {
			mapA[*r.CidrIpv6] = struct{}{}
		}
	}
	for _, r := range b {
		if r.CidrIpv6 == nil { // If b has a nil entry, it can't match
			return false
		}
		if _, ok := mapA[*r.CidrIpv6]; !ok {
			return false
		}
	}
	// Ensure the counts match exactly
	return len(mapA) == len(b)
}

// TestService runs the network checks by invoking the Lambda function(s).
func (r *LambdaTestRunner) TestService(ctx context.Context, subnets []checks.Subnet, serviceEndpoints map[string]string) (bool, error) {
	log.Infof("Lambda Runner: TestService phase starting for %d subnets and %d endpoints.", len(subnets), len(serviceEndpoints))

	if len(r.functionArns) == 0 {
		return false, fmt.Errorf("no lambda functions seem to be prepared (functionArns map is empty)")
	}
	if len(subnets) == 0 {
		log.Warn("No target subnets provided for this test set, skipping invocation.")
		return true, nil // No subnets means nothing to test here
	}
	if len(serviceEndpoints) == 0 {
		log.Warn("No service endpoints provided for this test set, skipping invocation.")
		return true, nil // No endpoints means nothing to test here
	}

	overallSuccess := true

	// Prepare the request payload once
	requestPayload := lambda_types.CheckRequest{Endpoints: serviceEndpoints} // Use shared type
	payloadBytes, err := json.Marshal(requestPayload)
	if err != nil {
		return false, fmt.Errorf("failed to marshal lambda request payload: %w", err)
	}

	// Invoke Lambda for each unique target subnet
	invokedSubnets := make(map[string]bool)
	for _, subnet := range subnets {
		// Clean the subnet ID *before* using it for lookup, consistent with Prepare phase
		var sb strings.Builder
		for _, r := range subnet.SubnetID {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				sb.WriteRune(r)
			}
		}
		cleanSubnetID := sb.String()

		// Basic validation after cleaning - should match validation in Prepare
		if !strings.HasPrefix(cleanSubnetID, "subnet-") || len(cleanSubnetID) < 8 {
			log.Errorf("❌ Invalid subnet ID format during lookup: '%s' (Original: '%s'). Skipping.", cleanSubnetID, subnet.SubnetID)
			overallSuccess = false // Mark as failure if subnet ID is invalid
			continue
		}

		if _, exists := invokedSubnets[cleanSubnetID]; exists {
			log.Debugf("Skipping already invoked subnet: %s", cleanSubnetID)
			continue
		}

		functionArn, ok := r.functionArns[cleanSubnetID] // Use cleaned subnet ID for lookup
		if !ok {
			log.Errorf("❌ No prepared Lambda function found for subnet %s. Skipping.", cleanSubnetID)
			overallSuccess = false
			invokedSubnets[cleanSubnetID] = true // Mark as invoked (even though failed) to avoid re-attempting
			continue                             // Skip this subnet if no function was prepared for it
		}

		log.Infof("🚀 Invoking Lambda function %s for subnet %s", functionArn, cleanSubnetID)

		invokeInput := &lambda.InvokeInput{
			FunctionName:   aws.String(functionArn),
			Payload:        payloadBytes,
			InvocationType: lambdatypes.InvocationTypeRequestResponse, // Synchronous invocation
			LogType:        lambdatypes.LogTypeTail,                   // Get logs in response
		}

		invokeOutput, err := r.lambdaClient.Invoke(ctx, invokeInput)
		if err != nil {
			log.Errorf("❌ Failed to invoke Lambda function %s for subnet %s: %v", functionArn, cleanSubnetID, err) // Use cleanSubnetID in log
			overallSuccess = false
			invokedSubnets[cleanSubnetID] = true // Mark as invoked even if failed
			continue
		}

		// Log Lambda execution logs if available
		if invokeOutput.LogResult != nil {
			log.Tracef("Lambda logs for %s (Subnet: %s):\n%s", functionArn, cleanSubnetID, *invokeOutput.LogResult) // Use cleanSubnetID in log
		}

		if invokeOutput.FunctionError != nil {
			log.Errorf("❌ Lambda function %s for subnet %s executed with error: %s", functionArn, cleanSubnetID, *invokeOutput.FunctionError) // Use cleanSubnetID in log
			overallSuccess = false
			invokedSubnets[cleanSubnetID] = true
			continue
		}

		// Process the response payload
		var responsePayload lambda_types.CheckResponse // Use shared type
		err = json.Unmarshal(invokeOutput.Payload, &responsePayload)
		if err != nil {
			log.Errorf("❌ Failed to unmarshal response payload from Lambda %s for subnet %s: %v", functionArn, cleanSubnetID, err) // Use cleanSubnetID in log
			log.Debugf("Raw payload: %s", string(invokeOutput.Payload))
			overallSuccess = false
			invokedSubnets[cleanSubnetID] = true
			continue
		}

		log.Infof("📋 Results from Lambda in subnet %s:", cleanSubnetID) // Use cleanSubnetID in log
		subnetSuccess := true
		for endpointName, result := range responsePayload.Results {
			if result.Success {
				log.Infof("  ✅ %s: OK", endpointName)
			} else {
				log.Errorf("  ❌ %s: FAILED (%s)", endpointName, result.Error)
				subnetSuccess = false
			}
		}

		if !subnetSuccess {
			overallSuccess = false
		}
		invokedSubnets[cleanSubnetID] = true
	}

	log.Info("Lambda Runner: TestService phase finished.")
	return overallSuccess, nil
}

// Cleanup removes the AWS resources created during Prepare.
func (r *LambdaTestRunner) Cleanup(ctx context.Context) error {
	log.Info("Lambda Runner: Cleanup phase starting...")
	var cleanupErrors []error
	deletedFunctionNames := make(map[string]string) // Store function name -> ARN for log group deletion

	// 1. Delete Lambda Functions
	if len(r.functionArns) > 0 {
		log.Infof("Deleting %d Lambda function(s)...", len(r.functionArns))
		for subnetID, functionArn := range r.functionArns {
			// Extract function name from ARN for log group deletion later
			// ARN format: arn:aws:lambda:region:account-id:function:function-name
			functionName := getFunctionNameFromARN(functionArn)
			if functionName == "" {
				log.Warnf("Could not extract function name from ARN %s, skipping log group cleanup for this function.", functionArn)
			} else {
				deletedFunctionNames[functionName] = functionArn // Store for later use
			}

			log.Debugf("Deleting Lambda function %s (Name: %s, Subnet: %s)", functionArn, functionName, subnetID)
			deleteInput := &lambda.DeleteFunctionInput{
				FunctionName: aws.String(functionArn),
			}
			_, err := r.lambdaClient.DeleteFunction(ctx, deleteInput)
			if err != nil {
				// Check if it's already gone
				var rnfe *lambdatypes.ResourceNotFoundException
				if errors.As(err, &rnfe) {
					log.Warnf("Lambda function %s not found, likely already deleted.", functionArn)
				} else {
					log.Errorf("❌ Failed to delete Lambda function %s: %v", functionArn, err)
					cleanupErrors = append(cleanupErrors, fmt.Errorf("failed to delete lambda %s: %w", functionArn, err))
				}
			} else {
				log.Infof("✅ Deleted Lambda function %s (Name: %s)", functionArn, functionName)
			}
		}
	} else {
		log.Info("No Lambda functions recorded to delete.")
	}

	// 2. Find and Delete Network Interfaces associated with the managed Security Group
	if r.securityGroupID != nil && r.config.LambdaSecurityGroupID == "" {
		sgID := *r.securityGroupID
		log.Infof("Searching for Network Interfaces attached to managed Security Group %s...", sgID)

		enis, err := r.findNetworkInterfacesForSecurityGroup(ctx, sgID)
		if err != nil {
			log.WithError(err).Errorf("❌ Failed to find network interfaces for SG %s. Skipping ENI cleanup.", sgID)
		} else if len(enis) > 0 {
			log.Infof("Found %d Network Interface(s) associated with SG %s. Attempting detachment and deletion...", len(enis), sgID)
			for eniID, eni := range enis {
				log.Infof("Processing ENI '%s' (status: %s) with attachment ID '%s' (status: %s)...", eniID, eni.eniStatus, eni.attachmentID, eni.attachmentStatus)
				if strings.HasPrefix(eni.attachmentID, "ela-attach-") {
					log.Infof("Leaving attachment ID '%s' as-is, as it will be automatically removed once the lambda is gone", eni.attachmentID)
					continue
				}
				if strings.HasPrefix(eni.description, "AWS Lambda") {
					log.Infof("Leaving ENI '%s' as-is, as it is an AWS Lambda that is cleaned up automatically", eniID)
					continue
				}

				attachmentID := eni.attachmentID
				if attachmentID != "" {
					detachInput := &ec2.DetachNetworkInterfaceInput{
						AttachmentId: aws.String(attachmentID),
						Force:        aws.Bool(true),
					}
					_, detachErr := r.ec2Client.DetachNetworkInterface(ctx, detachInput)
					if detachErr != nil {
						var apiErr smithy.APIError
						if errors.As(detachErr, &apiErr) && apiErr.ErrorCode() == "InvalidAttachmentID.NotFound" {
							log.Infof("ENI %s already detached.", eniID)
						} else {
							log.WithError(detachErr).Warnf("Failed to detach ENI '%s' with attachment ID '%s'", eniID, attachmentID)
							cleanupErrors = append(cleanupErrors, fmt.Errorf("Failed to detach ENI '%s' with attachment ID '%s': %w", eniID, attachmentID, detachErr))
						}
					}
					log.Infof("Detachment initiated for ENI '%s' with attachment ID '%s' ", eniID, attachmentID)
				}

				// Attempt deletion with retries
				deleteErr := r.deleteNetworkInterfaceWithRetry(ctx, eniID)
				if deleteErr != nil {
					log.WithError(deleteErr).Errorf("❌ Failed to delete ENI %s after retries.", eniID)
					cleanupErrors = append(cleanupErrors, fmt.Errorf("failed to delete ENI %s: %w", eniID, deleteErr))
					// Continue to try deleting other ENIs
				} else {
					log.Infof("✅ Deleted Network Interface %s", eniID)
				}
			}
		} else {
			log.Infof("No Network Interfaces found associated with SG %s.", sgID)
		}
	} else {
		log.Info("Skipping Network Interface cleanup as Security Group was user-provided or not found.")
	}

	// 3. Delete Security Group (only if managed by this tool, i.e., not provided via config)
	// Now attempt SG deletion *after* ENI cleanup attempt
	// if r.securityGroupID != nil && r.config.LambdaSecurityGroupID == "" {
	// 	sgID := *r.securityGroupID
	// 	log.Infof("Deleting managed Security Group %s...", sgID)
	// 	deleteSGInput := &ec2.DeleteSecurityGroupInput{
	// 		GroupId: r.securityGroupID,
	// 	}
	// 	_, err := r.ec2Client.DeleteSecurityGroup(ctx, deleteSGInput)
	// 	if err != nil {
	// 		var apiErr smithy.APIError
	// 		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "InvalidGroup.NotFound" {
	// 			log.Warnf("Security Group %s not found, likely already deleted.", sgID)
	// 		} else {
	// 			log.Errorf("❌ Failed to delete Security Group %s: %v", sgID, err)
	// 			cleanupErrors = append(cleanupErrors, fmt.Errorf("failed to delete security group %s: %w", sgID, err))
	// 		}
	// 	} else {
	// 		log.Infof("✅ Deleted Security Group %s", sgID)
	// 	}
	// } else
	if r.config.LambdaSecurityGroupID != "" { // Check if SG was provided via config
		log.Infof("Skipping deletion of user-provided Security Group: %s", r.config.LambdaSecurityGroupID)
	} else {
		log.Info("No deleting created SecurityGroup as it's garbage collected by AWS.")
	}

	// 4. Delete IAM Role (only if managed by this tool, i.e., not provided via config)
	if r.roleArn != nil && r.config.LambdaRoleArn == "" {
		roleName := lambdaRoleName // Assuming we always use the same name for managed roles
		log.Infof("Detaching policies and deleting managed IAM role %s...", roleName)

		// Detach policies first (only necessary if we created the role)
		policies := []string{
			"arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
			"arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole",
			"arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
		}
		for _, policyArn := range policies {
			log.Debugf("Detaching policy %s from role %s", policyArn, roleName)
			detachInput := &iam.DetachRolePolicyInput{
				RoleName:  aws.String(roleName),
				PolicyArn: aws.String(policyArn),
			}
			_, err := r.iamClient.DetachRolePolicy(ctx, detachInput)
			if err != nil {
				// Log error but continue trying to delete role
				log.Warnf("Failed to detach policy %s from role %s: %v", policyArn, roleName, err)
				// Don't add to cleanupErrors here, as role deletion might still succeed or fail for other reasons
			}
		}

		// Delete the inline policy first
		log.Debugf("Deleting inline policy %s from role %s", inlinePolicyName, roleName)
		deletePolicyInput := &iam.DeleteRolePolicyInput{
			RoleName:   aws.String(roleName),
			PolicyName: aws.String(inlinePolicyName),
		}
		_, err := r.iamClient.DeleteRolePolicy(ctx, deletePolicyInput)
		if err != nil {
			var nsee *types.NoSuchEntityException
			if errors.As(err, &nsee) {
				log.Warnf("Inline policy %s not found on role %s, likely already deleted or never attached.", inlinePolicyName, roleName)
				// Policy not found is not a blocking error for role deletion, reset err
				err = nil
			}
		}

		// Delete the role
		deleteInput := &iam.DeleteRoleInput{
			RoleName: aws.String(roleName),
		}
		_, err = r.iamClient.DeleteRole(ctx, deleteInput)
		if err != nil {
			var nsee *types.NoSuchEntityException
			if errors.As(err, &nsee) {
				log.Warnf("IAM role %s not found, likely already deleted.", roleName)
			} else {
				log.Errorf("❌ Failed to delete IAM role %s: %v", roleName, err)
				cleanupErrors = append(cleanupErrors, fmt.Errorf("failed to delete iam role %s: %w", roleName, err))
			}
		} else {
			log.Infof("✅ Deleted IAM role %s", roleName)
		}
	} else if r.config.LambdaRoleArn != "" { // Check if Role was provided via config
		log.Infof("Skipping deletion of user-provided IAM Role: %s", r.config.LambdaRoleArn)
	} else { // Neither managed nor provided (or r.roleArn was nil initially)
		log.Info("No managed IAM Role ARN recorded to delete.")
	}

	// 4. Delete CloudWatch Log Groups (always delete these as they are tied to the specific function run)
	if len(deletedFunctionNames) > 0 {
		log.Infof("Deleting %d CloudWatch Log Group(s)...", len(deletedFunctionNames))
		for functionName, functionArn := range deletedFunctionNames {
			logGroupName := fmt.Sprintf("/aws/lambda/%s", functionName)
			log.Debugf("Deleting CloudWatch Log Group %s (for function %s)", logGroupName, functionArn)

			deleteLogGroupInput := &cloudwatchlogs.DeleteLogGroupInput{
				LogGroupName: aws.String(logGroupName),
			}
			_, err := r.cloudwatchlogsClient.DeleteLogGroup(ctx, deleteLogGroupInput)
			if err != nil {
				var rnfe *cwltypes.ResourceNotFoundException // Use aliased type
				if errors.As(err, &rnfe) {
					log.Warnf("CloudWatch Log Group %s not found, likely already deleted or never created.", logGroupName)
				} else {
					log.Errorf("❌ Failed to delete CloudWatch Log Group %s: %v", logGroupName, err)
					cleanupErrors = append(cleanupErrors, fmt.Errorf("failed to delete log group %s: %w", logGroupName, err))
				}
			} else {
				log.Infof("✅ Deleted CloudWatch Log Group %s", logGroupName)
			}
		}
	} else {
		log.Info("No Lambda function names recorded to attempt log group deletion.")
	}

	if len(cleanupErrors) > 0 {
		log.Error("Lambda Runner: Cleanup phase completed with errors.")
		// Combine errors? For now, just return the first one or a generic error.
		return fmt.Errorf("cleanup failed with %d error(s): %w", len(cleanupErrors), cleanupErrors[0])
	}

	log.Info("Lambda Runner: Cleanup phase completed successfully.")
	return nil
}

// Helper function to extract function name from ARN
// Example ARN: arn:aws:lambda:us-west-2:123456789012:function:my-function
func getFunctionNameFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 6 && parts[5] == "function" {
		// Handle potential version/alias suffix like my-function:1 or my-function:$LATEST
		nameParts := strings.Split(parts[6], ":")
		return nameParts[0]
	}
	return ""
}

type networkInterface struct {
	eniID            string
	eniStatus        ec2types.NetworkInterfaceStatus
	description      string
	attachmentID     string
	attachmentStatus ec2types.AttachmentStatus
}

// findNetworkInterfacesForSecurityGroup finds ENIs and their Attachment IDs associated with a specific security group.
// Returns a map[eniID]attachmentID.
func (r *LambdaTestRunner) findNetworkInterfacesForSecurityGroup(ctx context.Context, sgID string) (map[string]*networkInterface, error) {
	eniAttachments := make(map[string]*networkInterface)
	input := &ec2.DescribeNetworkInterfacesInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("group-id"),
				Values: []string{sgID},
			},
		},
	}

	paginator := ec2.NewDescribeNetworkInterfacesPaginator(r.ec2Client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe network interfaces for SG %s: %w", sgID, err)
		}

		for _, eni := range page.NetworkInterfaces {
			if eni.NetworkInterfaceId == nil {
				log.Warnf("Found ENI for SG %s, but it has no interfaceId. Cannot detach automatically.", sgID)
				continue
			}

			eniID := *eni.NetworkInterfaceId
			nif := networkInterface{
				eniID:       eniID,
				description: *eni.Description,
				eniStatus:   eni.Status,
			}
			if eni.Attachment != nil && eni.Attachment.AttachmentId != nil {
				nif.attachmentStatus = eni.Attachment.Status
				nif.attachmentID = *eni.Attachment.AttachmentId
			}
			eniAttachments[eniID] = &nif
		}
	}
	return eniAttachments, nil
}

// deleteNetworkInterfaceWithRetry attempts to delete an ENI with retries.
func (r *LambdaTestRunner) deleteNetworkInterfaceWithRetry(ctx context.Context, eniID string) error {
	maxDuration := 3 * time.Minute
	maxWaitDuration := time.NewTimer(maxDuration)
	baseDelay := 20 * time.Second
	var lastErr error

	// for ;; {
	// 	enis, err := r.ec2Client.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{
	// 		NetworkInterfaceIds: []string{eniID},
	// 	})
	// 	if err != nil {
	// 		log.WithError(err).Warnf("Failed to describe ENI %s before deletion attempt.", eniID)
	// 		return fmt.Errorf("failed to describe ENI %s: %w", eniID, err)
	// 	}
	// 	if len(enis.NetworkInterfaces) == 0 {
	// 		log.Warnf("ENI %s not found during describe before deletion attempt.", eniID)
	// 		return nil
	// 	}
	// 	eni := enis.NetworkInterfaces[0]
	// 	if eni.Status == ec2types.NetworkInterfaceStatusDetaching {
	// 		log.Infof("Found ENI %s with status %s before deletion attempt.", eniID, eni.Status)
	// 	}
	// }

loop:
	for attempt := 1; ; attempt++ {
		log.Debugf("Attempt %d to delete ENI %s...", attempt, eniID)
		_, err := r.ec2Client.DeleteNetworkInterface(ctx, &ec2.DeleteNetworkInterfaceInput{
			NetworkInterfaceId: aws.String(eniID),
		})
		if err == nil {
			log.Debugf("Successfully deleted ENI %s on attempt %d.", eniID, attempt)
			return nil // Success
		}

		lastErr = err
		log.WithError(err).Warnf("Attempt %d failed to delete ENI %s.", attempt, eniID)

		// Check if it's already deleted
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "InvalidNetworkInterfaceID.NotFound" {
			log.Infof("ENI %s not found during delete attempt %d, assuming already deleted.", eniID, attempt)
			return nil // Treat as success
		}

		// Wait before retrying
		select {
		case <-time.After(baseDelay):
			// Continue loop
		case <-maxWaitDuration.C:
			log.Warnf("Timeout struck while waiting to retry ENI %s deletion.", eniID)
			break loop
		case <-ctx.Done():
			log.Warnf("Context cancelled while waiting to retry ENI %s deletion.", eniID)
			return ctx.Err()
		}
	}

	return fmt.Errorf("failed to delete ENI %s after %d attempts: %w", eniID, maxDuration, lastErr)
}

// LoadLambdaRunnerFromTags creates a new LambdaTestRunner instance by discovering existing
// AWS resources based on known names and the standard network check tag.
func LoadLambdaRunnerFromTags(ctx context.Context, networkConfig *checks.NetworkConfig) (*LambdaTestRunner, error) {
	runner, err := NewLambdaTestRunner(ctx, networkConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create base LambdaTestRunner: %w", err)
	}

	log.Info("Attempting to load existing Lambda runner resources from tags...")

	// Discover Lambda Functions by tag
	log.Debugf("Searching for Lambda functions with tag %s=%s", NetworkCheckTagKey, NetworkCheckTagValue) // Use exported constants
	listFuncPaginator := lambda.NewListFunctionsPaginator(runner.lambdaClient, &lambda.ListFunctionsInput{})
	foundFunctions := 0
	for listFuncPaginator.HasMorePages() {
		page, err := listFuncPaginator.NextPage(ctx)
		if err != nil {
			log.WithError(err).Warn("Failed to list Lambda functions page, discovery might be incomplete.")
			break // Stop processing on error, but continue with what we have
		}
		for _, function := range page.Functions {
			tagsOutput, err := runner.lambdaClient.ListTags(ctx, &lambda.ListTagsInput{Resource: function.FunctionArn})
			if err != nil {
				log.WithError(err).Warnf("Failed to list tags for function %s, skipping.", *function.FunctionArn)
				continue
			}
			if val, ok := tagsOutput.Tags[NetworkCheckTagKey]; ok && val == NetworkCheckTagValue { // Use exported constants
				log.Debugf("Found tagged Lambda function: %s", *function.FunctionArn)
				// We don't know the original subnet ID here, store by ARN for cleanup
				runner.functionArns[*function.FunctionArn] = *function.FunctionArn
				foundFunctions++
			}
		}
	}
	if foundFunctions > 0 {
		log.Infof("Discovered %d existing Lambda function(s) tagged for cleanup.", foundFunctions)
	} else {
		log.Info("No existing Lambda functions found with the network check tag.")
	}

	// Discover IAM Role by name (and optionally check tag)
	log.Debugf("Checking for managed IAM role: %s", lambdaRoleName)
	getRoleInput := &iam.GetRoleInput{RoleName: aws.String(lambdaRoleName)}
	getRoleOutput, err := runner.iamClient.GetRole(ctx, getRoleInput)
	if err == nil {
		// Verify tag - GetRole doesn't return tags directly, need ListRoleTags
		tagsOutput, tagErr := runner.iamClient.ListRoleTags(ctx, &iam.ListRoleTagsInput{RoleName: aws.String(lambdaRoleName)})
		hasTag := false
		if tagErr == nil {
			for _, tag := range tagsOutput.Tags {
				if aws.ToString(tag.Key) == NetworkCheckTagKey && aws.ToString(tag.Value) == NetworkCheckTagValue { // Use exported constants
					hasTag = true
					break
				}
			}
		} else {
			log.WithError(tagErr).Warnf("Could not list tags for role %s", lambdaRoleName)
		}

		if hasTag {
			log.Infof("Discovered existing managed IAM role: %s", *getRoleOutput.Role.Arn)
			runner.roleArn = getRoleOutput.Role.Arn
		} else {
			log.Warnf("Found IAM role named %s, but it doesn't have the expected tag (%s=%s). It will not be managed/cleaned up.", lambdaRoleName, NetworkCheckTagKey, NetworkCheckTagValue) // Use exported constants
		}
	} else {
		var nsee *types.NoSuchEntityException
		if !errors.As(err, &nsee) {
			log.WithError(err).Warnf("Failed to get IAM role %s", lambdaRoleName)
		} else {
			log.Info("No existing managed IAM role found.")
		}
	}

	// Discover Security Group by name and tag
	log.Debugf("Checking for managed Security Group: %s", lambdaSecurityGroupName)
	// We need a VPC ID to search for the SG. If subnets are configured, use the first one.
	// If no subnets are configured (e.g., pure cleanup run), we might not be able to find the SG reliably by name alone across VPCs.
	// For cleanup, maybe we should list *all* SGs with the tag? Or require VPC context?
	// Let's assume for now cleanup usually runs with the same config, so we can get VPC ID.
	vpcID, err := runner.getVpcIDFromSubnets(ctx) // Re-use existing helper
	if err != nil {
		log.WithError(err).Warn("Could not determine VPC ID from config, Security Group discovery might be limited.")
		// Potentially list SGs across all VPCs with the tag? Riskier. For now, skip SG discovery if VPC is unknown.
	} else {
		describeSGInput := &ec2.DescribeSecurityGroupsInput{
			Filters: append(NetworkCheckTagsFilter, // Use exported var
				ec2types.Filter{Name: aws.String("vpc-id"), Values: []string{*vpcID}},
				ec2types.Filter{Name: aws.String("group-name"), Values: []string{lambdaSecurityGroupName}},
			),
		}
		describeSGOutput, err := runner.ec2Client.DescribeSecurityGroups(ctx, describeSGInput)
		if err != nil {
			log.WithError(err).Warnf("Could not describe security groups (maybe transient error or SG doesn't exist)")
		} else if len(describeSGOutput.SecurityGroups) > 0 {
			// Found the managed SG
			sgID := describeSGOutput.SecurityGroups[0].GroupId
			log.Infof("Discovered existing managed Security Group: %s", *sgID)
			runner.securityGroupID = sgID
		} else {
			log.Info("No existing managed Security Group found.")
		}
	}

	log.Info("Lambda runner resource discovery complete.")
	return runner, nil
}
