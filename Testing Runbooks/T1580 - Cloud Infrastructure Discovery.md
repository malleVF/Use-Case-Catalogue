---
tags: [T1580, atomic_test]
filename: "[[T1580 - Cloud Infrastructure Discovery]]"
---
# T1580 - Cloud Infrastructure Discovery

## Atomic Test #1 - AWS - EC2 Enumeration from Cloud Instance
This atomic runs several API calls (sts:GetCallerIdentity, s3:ListBuckets, iam:GetAccountSummary, iam:ListRoles, iam:ListUsers, iam:GetAccountAuthorizationDetails, ec2:DescribeSnapshots, cloudtrail:DescribeTrails, guardduty:ListDetectors) from the context of an EC2 instance role. This simulates an attacker compromising an EC2 instance and running initial discovery commands on it. This atomic test leverages a tool called stratus-red-team built by DataDog (https://github.com/DataDog/stratus-red-team). Stratus Red Team is a self-contained binary. You can use it to easily detonate offensive attack techniques against a live cloud environment. Ref: https://stratus-red-team.cloud/attack-techniques/AWS/aws.discovery.ec2-enumerate-from-instance/

**Supported Platforms:** Linux, macOS, Iaas:aws


**auto_generated_guid:** 99ee161b-dcb1-4276-8ecb-7cfdcb207820





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| stratus_path | Path of stratus binary | path | $PathToAtomicsFolder/T1580/src|
| aws_region | AWS region to detonate | string | us-west-2|


#### Attack Commands: Run with `sh`! 


```sh
export AWS_REGION=#{aws_region}
cd #{stratus_path}
echo "Stratus: Start Warmup."
./stratus warmup aws.discovery.ec2-enumerate-from-instance
echo "Stratus: Start Detonate."
./stratus detonate aws.discovery.ec2-enumerate-from-instance
```

#### Cleanup Commands:
```sh
cd #{stratus_path}
echo "Stratus: Start Cleanup."
./stratus cleanup aws.discovery.ec2-enumerate-from-instance
echo "Removing Stratus artifacts from local machine."
rm -rf stratus*
```



#### Dependencies:  Run with `sh`!
##### Description: Stratus binary must be present at the (#{stratus_path}/stratus)
##### Check Prereq Commands:
```sh
if test -f "#{stratus_path}/stratus"; then exit 0; else exit 1; fi
```
##### Get Prereq Commands:
```sh
if [ "$(uname)" = "Darwin" ]
then DOWNLOAD_URL=$(curl -s https://api.github.com/repos/DataDog/stratus-red-team/releases/latest | grep browser_download_url | grep -i Darwin_x86_64 | cut -d '"' -f 4); wget -q -O #{stratus_path}/stratus-red-team-latest.tar.gz $DOWNLOAD_URL
  tar -xzvf #{stratus_path}/stratus-red-team-latest.tar.gz --directory #{stratus_path}/
elif [ "$(expr substr $(uname) 1 5)" = "Linux" ]
then DOWNLOAD_URL=$(curl -s https://api.github.com/repos/DataDog/stratus-red-team/releases/latest | grep browser_download_url | grep -i linux_x86_64 | cut -d '"' -f 4); wget -q -O #{stratus_path}/stratus-red-team-latest.tar.gz $DOWNLOAD_URL
  tar -xzvf #{stratus_path}/stratus-red-team-latest.tar.gz --directory #{stratus_path}/
fi
```
##### Description: Check if ~/.aws/credentials file has a default stanza is configured
##### Check Prereq Commands:
```sh
cat ~/.aws/credentials | grep "default"
```
##### Get Prereq Commands:
```sh
echo "Please install the aws-cli and configure your AWS default profile using: aws configure"
```




<br/>
