package cmd

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
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
	Subnets         map[string]bool
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
	if len(InstanceIds) == 0 {
		instances, err := svc.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
			Filters: []types.Filter{
				{
					Name:   aws.String("tag:gitpod.io/network-check"),
					Values: []string{"true"},
				},
				{
					Name:   aws.String("instance-state-name"),
					Values: []string{"pending", "running", "shutting-down", "stopping", "stopped"},
				},
			},
		})
		if err != nil {
			log.WithError(err).Error("Failed to list instances, please cleanup instances manually")
		} else if len(instances.Reservations) == 0 {
			log.Info("No instances found.")
		}

		if instances != nil {
			for _, r := range instances.Reservations {
				for _, i := range r.Instances {
					InstanceIds = append(InstanceIds, *i.InstanceId)
				}
			}
		}
	}

	if len(InstanceIds) > 0 {
		log.Info("ℹ️  Terminating EC2 instances")
		_, err := svc.TerminateInstances(ctx, &ec2.TerminateInstancesInput{
			InstanceIds: InstanceIds,
		})
		if err != nil {
			log.WithError(err).WithField("instanceIds", InstanceIds).Warnf("Failed to cleanup instances, please cleanup manually")
		}

		terminateWaiter := ec2.NewInstanceTerminatedWaiter(svc, func(itwo *ec2.InstanceTerminatedWaiterOptions) {
			itwo.MaxDelay = 15 * time.Second
			itwo.MinDelay = 5 * time.Second
		})
		log.Info("ℹ️  Waiting for EC2 instances to Terminate (times out in 5 minutes)")
		err = terminateWaiter.Wait(ctx, &ec2.DescribeInstancesInput{InstanceIds: InstanceIds}, *aws.Duration(5 * time.Minute))
		if err != nil {
			log.WithError(err).Warn("Failed to wait for instances to terminate")
			log.Warn("ℹ️  Waiting 2 minutes so network interfaces are deleted")
			time.Sleep(2 * time.Minute)
		} else {
			log.Info("✅ Instances terminated")
		}
	}

	if len(Roles) == 0 {
		paginator := iam.NewListInstanceProfilesPaginator(iamsvc, &iam.ListInstanceProfilesInput{})
		for paginator.HasMorePages() {
			output, err := paginator.NextPage(ctx)
			if err != nil {
				log.WithError(err).Warn("Failed to list roles, please cleanup manually")
				break
			}

			for _, ip := range output.InstanceProfiles {
				if *ip.InstanceProfileName == gitpodInstanceProfile {
					{
						InstanceProfile = *ip.InstanceProfileName
						if len(ip.Roles) > 0 {
							for _, role := range ip.Roles {
								Roles = append(Roles, *role.RoleName)
							}
						}
					}
				}
			}
		}
		if len(Roles) == 0 {
			log.Info("No roles found.")
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
				continue
			}

			log.Infof("✅ Role '%v' deleted", role)
		}

		_, err := iamsvc.DeleteInstanceProfile(ctx, &iam.DeleteInstanceProfileInput{
			InstanceProfileName: aws.String(InstanceProfile),
		})

		if err != nil {
			log.WithError(err).WithField("instanceProfile", InstanceProfile).Warnf("Failed to clean up instance profile, please cleanup manually")
		}

		log.Info("✅ Instance profile deleted")
	}

	if len(SecurityGroups) == 0 {
		securityGroups, err := svc.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
			Filters: []types.Filter{
				{
					Name:   aws.String("tag:gitpod.io/network-check"),
					Values: []string{"true"},
				},
			},
		})

		if err != nil {
			log.WithError(err).Error("Failed to list security groups, please cleanup manually")
		} else if len(securityGroups.SecurityGroups) == 0 {
			log.Info("No security groups found.")
		}

		if securityGroups != nil {
			for _, sg := range securityGroups.SecurityGroups {
				SecurityGroups = append(SecurityGroups, *sg.GroupId)
			}
		}
	}

	if len(SecurityGroups) > 0 {
		for _, sg := range SecurityGroups {
			deleteSGInput := &ec2.DeleteSecurityGroupInput{
				GroupId: aws.String(sg),
			}

			_, err := svc.DeleteSecurityGroup(ctx, deleteSGInput)
			if err != nil {
				log.WithError(err).WithField("securityGroup", sg).Warnf("Failed to clean up security group, please cleanup manually")
				continue
			}
			log.Infof("✅ Security group '%v' deleted", sg)
		}
	}
}
