---
tags: [T1530, atomic_test]
filename: "[[T1530 - Data from Cloud Storage Object]]"
---
# T1530 - Data from Cloud Storage Object

## Atomic Test #1 - Azure - Enumerate Azure Blobs with MicroBurst
Upon successful execution, this test will utilize a wordlist to enumerate the public facing containers and blobs of a specified Azure storage account. 
See https://www.netspi.com/blog/technical/cloud-penetration-testing/anonymously-enumerating-azure-file-resources/ .

**Supported Platforms:** Iaas:azure


**auto_generated_guid:** 3dab4bcc-667f-4459-aea7-4162dd2d6590





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| base | Azure blob keyword to enumerate (Example, storage account name) | string | secure|
| output_file | File to output results to | string | $env:temp&#92;T1530Test1.txt|
| wordlist | File path to keywords for search permutations | string | PathToAtomicsFolder&#92;..&#92;ExternalPayloads&#92;permutations.txt|


#### Attack Commands: Run with `powershell`! 


```powershell
import-module "PathToAtomicsFolder\..\ExternalPayloads\Invoke-EnumerateAzureBlobs.ps1"
Invoke-EnumerateAzureBlobs -base #{base} -permutations "#{wordlist}" -outputfile "#{output_file}"
```

#### Cleanup Commands:
```powershell
remove-item #{output_file} -erroraction silentlycontinue
```



#### Dependencies:  Run with `powershell`!
##### Description: The Invoke-EnumerateAzureBlobs module must exist in PathToAtomicsFolder\..\ExternalPayloads.
##### Check Prereq Commands:
```powershell
if (test-path "PathToAtomicsFolder\..\ExternalPayloads\Invoke-EnumerateAzureBlobs.ps1"){exit 0} else {exit 1}
```
##### Get Prereq Commands:
```powershell
New-Item -Type Directory "PathToAtomicsFolder\..\ExternalPayloads\" -ErrorAction Ignore -Force | Out-Null
invoke-webrequest "https://raw.githubusercontent.com/NetSPI/MicroBurst/156c4e9f4253b482b2b68eda4651116b9f0f2e17/Misc/Invoke-EnumerateAzureBlobs.ps1" -outfile "PathToAtomicsFolder\..\ExternalPayloads\Invoke-EnumerateAzureBlobs.ps1"
```
##### Description: The wordlist file for search permutations must exist in PathToAtomicsFolder\..\ExternalPayloads.
##### Check Prereq Commands:
```powershell
if (test-path "#{wordlist}"){exit 0} else {exit 1}
```
##### Get Prereq Commands:
```powershell
invoke-webrequest "https://raw.githubusercontent.com/NetSPI/MicroBurst/156c4e9f4253b482b2b68eda4651116b9f0f2e17/Misc/permutations.txt" -outfile "#{wordlist}"
```




<br/>
<br/>

## Atomic Test #2 - Azure - Scan for Anonymous Access to Azure Storage (Powershell)
Upon successful execution, this test will test for anonymous access to Azure storage containers by invoking a web request and outputting the results to a file. 
The corresponding response could then be interpreted to determine whether or not the resource/container exists, as well as other information. 
See https://ninocrudele.com/the-three-most-effective-and-dangerous-cyberattacks-to-azure-and-countermeasures-part-2-attack-the-azure-storage-service

**Supported Platforms:** Iaas:azure


**auto_generated_guid:** 146af1f1-b74e-4aa7-9895-505eb559b4b0





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| base_name | Azure storage account name to test | string | T1530Test2|
| output_file | File to output results to | string | $env:temp&#92;T1530Test2.txt|
| container_name | Container name to search for (optional) | string | |
| blob_name | Blob name to search for (optional) | string | |


#### Attack Commands: Run with `powershell`! 


```powershell
try{$response = invoke-webrequest "https://#{base_name}.blob.core.windows.net/#{container_name}/#{blob_name}" -method "GET"}
catch [system.net.webexception]
{if($_.Exception.Response -ne $null)
{$Response = $_.Exception.Response.GetResponseStream()
$ReadResponse = New-Object System.IO.StreamReader($Response)
$ReadResponse.BaseStream.Position = 0
$responseBody = $ReadResponse.ReadToEnd()}
else {$responseBody = "The storage account could not be anonymously accessed."}}
"Response received for #{base_name}.blob.core.windows.net/#{container_name}/#{blob_name}: $responsebody" | out-file -filepath #{output_file} -append
```

#### Cleanup Commands:
```powershell
remove-item #{output_file} -erroraction silentlycontinue
```





<br/>
<br/>

## Atomic Test #3 - AWS - Scan for Anonymous Access to S3
Upon successful execution, this test will test for anonymous access to AWS S3 buckets and dumps all the files to a local folder.

**Supported Platforms:** Iaas:aws


**auto_generated_guid:** 979356b9-b588-4e49-bba4-c35517c484f5





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| s3_bucket_name | Name of the bucket | string | redatomic-test2|


#### Attack Commands: Run with `sh`! 


```sh
aws --no-sign-request s3 cp --recursive s3://#{s3_bucket_name} /tmp/#{s3_bucket_name}
```

#### Cleanup Commands:
```sh
aws s3 rb s3://#{s3_bucket_name} --force 
rm -rf /tmp/#{s3_bucket_name}
```



#### Dependencies:  Run with `sh`!
##### Description: Check if ~/.aws/credentials file has a default stanza is configured
##### Check Prereq Commands:
```sh
cat ~/.aws/credentials | grep "default"
aws s3api create-bucket --bucket #{s3_bucket_name}
aws s3api put-bucket-policy --bucket #{s3_bucket_name} --policy file://$PathToAtomicsFolder/T1530/src/policy.json
touch /tmp/T1530.txt
aws s3 cp /tmp/T1530.txt s3://#{s3_bucket_name}
```
##### Get Prereq Commands:
```sh
echo Please install the aws-cli and configure your AWS default profile using: aws configure
```




<br/>
