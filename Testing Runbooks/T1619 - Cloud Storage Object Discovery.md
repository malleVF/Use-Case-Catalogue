---
tags: [T1619, atomic_test]
filename: "[[T1619 - Cloud Storage Object Discovery]]"
---
# T1619 - Cloud Storage Object Discovery

## Atomic Test #1 - AWS S3 Enumeration
This test will enumerate all the S3 buckets in the user account and lists all the files in each bucket.

**Supported Platforms:** Iaas:aws


**auto_generated_guid:** 3c7094f8-71ec-4917-aeb8-a633d7ec4ef5






#### Attack Commands: Run with `sh`! 


```sh
for bucket in "$(aws s3 ls | cut -d " " -f3)"; do aws s3api list-objects-v2 --bucket $bucket --output text; done
```




#### Dependencies:  Run with `sh`!
##### Description: Check if ~/.aws/credentials file has a default stanza is configured
##### Check Prereq Commands:
```sh
cat ~/.aws/credentials | grep "default"
```
##### Get Prereq Commands:
```sh
echo Please install the aws-cli and configure your AWS default profile using: aws configure
```




<br/>
