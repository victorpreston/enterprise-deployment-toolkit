package cmd

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iam_types "github.com/aws/aws-sdk-go-v2/service/iam/types"
	log "github.com/sirupsen/logrus"
)

// this will be useful when we are cleaning up things at the end
var (
	InstanceIds     []string
	SecurityGroups  []string
	Roles           []string
	InstanceProfile string
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
