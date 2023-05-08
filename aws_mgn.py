## AWS Application Migration Service API Documentation

import boto3
import logging
from botocore.exceptions import ClientError
import json


def get_subnet_id() -> str:
    ec2 = boto3.client('ec2')
    subnets = []
    vpcs = []

    response = ec2.describe_subnets(
        Filters=[
            {
                'Name': 'tag:subnet-type',
                'Values': [
                    'mgn-staging-area',
                ]
            },
        ],
        MaxResults=10
    )

    for subnet in response['Subnets']:
        subnets.append(subnet['SubnetId'])
        vpcs.append((subnet['VpcId']))
    return subnets[0]


def create_replication_configuration_template():
    client = boto3.client('mgn')
    subnet = get_subnet_id()

    try:
        create_replication_template = client.create_replication_configuration_template(
            associateDefaultSecurityGroup=True,
            bandwidthThrottling=1000,
            createPublicIP=True,
            dataPlaneRouting='PUBLIC_IP',
            defaultLargeStagingDiskType='GP3',
            ebsEncryption='DEFAULT',
            replicationServerInstanceType='t3.medium',
            replicationServersSecurityGroupsIDs=[],  # get the default sg
            useDedicatedReplicationServer=False,
            stagingAreaSubnetId=subnet,
            stagingAreaTags={
                'Project': 'Migration'
            }
        )
        logging.info(create_replication_template)
    except ClientError as e:
        logging.info("Error creating the replication template", e)


def create_launch_configuration_template():
    client = boto3.client('mgn')

    try:
        create_launch_template = client.create_launch_configuration_template(
            associatePublicIpAddress=True,
            bootMode='LEGACY_BIOS',
            copyPrivateIp=False,
            copyTags=True,
            enableMapAutoTagging=False,
            largeVolumeConf={
                'iops': 3000,
                'throughput': 125,
                'volumeType': 'gp3'
            },
            launchDisposition='STARTED',
            licensing={
                'osByol': False
            },
            mapAutoTaggingMpeID='string',
            postLaunchActions={
                'cloudWatchLogGroupName': 'MGN-Server',
                'deployment': 'TEST_AND_CUTOVER',
                's3LogBucket': 'MGN-Server',
                's3OutputKeyPrefix': '/migration-output',
                # 'ssmDocuments': [
                #    {
                #        'actionName': 'MGN-Migration',
                #        'mustSucceedForCutover': True,
                #        'parameters': {
                #            'string': [
                #                {
                #                    'parameterName': 'string',
                #                   'parameterType': 'STRING'
                #                },
                #            ]
                #        },
                #        'ssmDocumentName': 'string',
                #        'timeoutSeconds': 123
                #    },
                # ]
            },
            smallVolumeConf={
                'iops': 3000,
                'throughput': 125,
                'volumeType': 'gp3'
            },
            smallVolumeMaxSize=123,
            tags={
                'Project': 'MGN'
            },
            targetInstanceTypeRightSizingMethod='BASIC'
        )
        logging.info(create_launch_template)
    except ClientError as e:
        logging.info("Error creating the launch template", e)


def create_iam_roles():
    iam = boto3.client('iam')

    iam_roles = ["AWSApplicationMigrationReplicationServerRole", "AWSApplicationMigrationConversionServerRole",
                 "AWSApplicationMigrationMGHRole", "AWSApplicationMigrationLaunchInstanceWithDrsRole",
                 "AWSApplicationMigrationLaunchInstanceWithSsmRole", "AWSApplicationMigrationAgentRole"]

    account_id = boto3.client("sts").get_caller_identity()["Account"]

    for role_name in iam_roles:
        if role_name == "AWSApplicationMigrationMGHRole":
            principle = "mgn.amazonaws.com"
            assume_role_policy_document = {"Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Principal": {"Service": principle}, "Action": "sts:AssumeRole"}]}
            assume_role_policy = assume_role_policy_document
        elif role_name == "AWSApplicationMigrationAgentRole":
            assumeRolePolicyDocumentMigrationAgent = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "mgn.amazonaws.com"
                        },
                        "Action": [
                            "sts:AssumeRole",
                            "sts:SetSourceIdentity"
                        ],
                        "Condition": {
                            "StringLike": {
                                "srs:SourceIdentity": "s-*",
                                "aws:SourceAccount": account_id
                            }
                        }
                    }
                ]
            }
            assume_role_policy = assumeRolePolicyDocumentMigrationAgent
        else:
            principle = "ec2.amazonaws.com"
            assume_role_policy_document = {"Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Principal": {"Service": principle}, "Action": "sts:AssumeRole"}]}
            assume_role_policy = assume_role_policy_document

        try:
            response = iam.create_role(
                Path='/service-role/',
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(assume_role_policy),
                Description='MGN Migration Role',
                MaxSessionDuration=3600,
                Tags=[
                    {
                        'Key': 'Migration',
                        'Value': 'MGN'
                    },
                ]
            )

        except ClientError as e:
            if e.response['Error']['Code'] == 'EntityAlreadyExists':
                logging.info("{0} already exist".format(role_name))
            else:
                logging.info("Unexpected error: %s" % e)

        if role_name == "AWSApplicationMigrationReplicationServerRole":
            awsApplicationMigrationReplicationServerPolicy = iam.attach_role_policy(
                RoleName=role_name,
                PolicyArn='arn:aws:iam::aws:policy/service-role/AWSApplicationMigrationReplicationServerPolicy'
            )
            logging.info(awsApplicationMigrationReplicationServerPolicy)
        elif role_name == "AWSApplicationMigrationAgentRole":
            awsApplicationMigrationAgentPolicy_v2 = iam.attach_role_policy(
                RoleName=role_name,
                PolicyArn='arn:aws:iam::aws:policy/service-role/AWSApplicationMigrationAgentPolicy_v2'
            )
            logging.info(awsApplicationMigrationAgentPolicy_v2)
        elif role_name == "AWSApplicationMigrationConversionServerRole":
            awsApplicationMigrationConversionServerPolicy = iam.attach_role_policy(
                RoleName='AWSApplicationMigrationConversionServerRole',
                PolicyArn='arn:aws:iam::aws:policy/service-role/AWSApplicationMigrationConversionServerPolicy'
            )
            logging.info(awsApplicationMigrationConversionServerPolicy)
        elif role_name == "AWSApplicationMigrationMGHRole":
            awsApplicationMigrationMGHAccess = iam.attach_role_policy(
                RoleName='AWSApplicationMigrationMGHRole',
                PolicyArn='arn:aws:iam::aws:policy/service-role/AWSApplicationMigrationMGHAccess'
            )
            logging.info(awsApplicationMigrationMGHAccess)
        elif role_name == "AWSApplicationMigrationLaunchInstanceWithDrsRole":
            amazonSSMManagedInstanceCore = iam.attach_role_policy(
                RoleName='AWSApplicationMigrationLaunchInstanceWithDrsRole',
                PolicyArn='arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore'
            )
            logging.info(amazonSSMManagedInstanceCore)
            awsElasticDisasterRecoveryEc2InstancePolicy = iam.attach_role_policy(
                RoleName='AWSApplicationMigrationLaunchInstanceWithDrsRole',
                PolicyArn='arn:aws:iam::aws:policy/service-role/AWSElasticDisasterRecoveryEc2InstancePolicy'
            )
            logging.info(awsElasticDisasterRecoveryEc2InstancePolicy)
        elif role_name == "AWSApplicationMigrationLaunchInstanceWithSsmRole":
            amazonSSMManagedInstanceCore = iam.attach_role_policy(
                RoleName='AWSApplicationMigrationLaunchInstanceWithSsmRole',
                PolicyArn='arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore'
            )
            logging.info(amazonSSMManagedInstanceCore)


def put_template_action_cw():
    client = boto3.client('mgn')

    response = client.put_template_action(
        actionID='CloudWatch agent installation',
        actionName='CloudWatch agent installation',
        active=True,
        category='OBSERVABILITY',
        description='string',
        documentIdentifier='AWSEC2-ApplicationInsightsCloudwatchAgentInstallAndConfigure',
        # documentVersion='string',
        externalParameters={
            'string': {
                'dynamicPath': 'string'
            }
        },
        launchConfigurationTemplateID='lct-15d02a5cc84a58e74',
        # mustSucceedForCutover=True|False,
        # operatingSystem='string',
        order=1001,
        parameters={
            'parameterStoreName': [
                {
                    'parameterName': 'test_parameter',  ##parameterStore parameter name. create them with terraform
                    'parameterType': 'STRING'
                },
            ]
        },
        timeoutSeconds=60
    )

    return response


def create_ami():
    client = boto3.client('mgn')

    response = client.put_template_action(
        actionID='Create AMI from instance',
        actionName='Create AMI from instance',
        active=True,
        category='BACKUP',
        # description='string',
        documentIdentifier='AWS-CreateImage',
        # documentVersion='string',
        externalParameters={
            'string': {
                'dynamicPath': 'string'
            }
        },
        launchConfigurationTemplateID='lct-15d02a5cc84a58e74',
        # mustSucceedForCutover=True|False,
        # operatingSystem='string',
        order=1002,
        # parameters={
        #     'InstanceId': [
        #         {
        #             'parameterName': 'instanceId',
        #             'parameterType': 'STRING'
        #         },
        #     ]
        # },
        timeoutSeconds=60
    )

    return response


def main() -> None:
    client = boto3.client('mgn')

    client.initialize_service()
    # Create necessary iam roles
    create_iam_roles()
    # Create Replication Template
    create_replication_configuration_template()
    # Create Launch Template
    create_launch_configuration_template()
    # Create Post Launch Configuration
    put_template_action_cw()
    # Create Post Launch Configuration
    create_ami()
