---
tags: [T1526, atomic_test]
filename: "[[T1526 - Cloud Service Discovery]]"
---
# T1526 - Cloud Service Discovery

## Atomic Test #1 - Azure - Dump Subscription Data with MicroBurst
Upon successful execution, this test will enumerate all resources that are contained within a valid Azure subscription. 
The resources enumerated will display on screen, as well as several csv files and folders will be output to a specified directory, listing what resources were discovered by the script. 
See https://dev.to/cheahengsoon/enumerating-subscription-information-with-microburst-35a1

**Supported Platforms:** Iaas:azure


**auto_generated_guid:** 1e40bb1d-195e-401e-a86b-c192f55e005c





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| username | Azure AD username | string | |
| password | Azure AD password | string | T1082Az|
| output_directory | Directory to output results to | string | $env:temp&#92;T1526Test1|
| subscription_name | Azure subscription name to scan | string | |


#### Attack Commands: Run with `powershell`! 


```powershell
import-module "PathToAtomicsFolder\..\ExternalPayloads\Get-AzDomainInfo.ps1"
$Password = ConvertTo-SecureString -String "#{password}" -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "#{username}", $Password
Connect-AzAccount -Credential $Credential | out-null
Get-AzDomainInfo -folder #{output_directory} -subscription "#{subscription_name}" -verbose
```

#### Cleanup Commands:
```powershell
remove-item #{output_directory} -recurse -force -erroraction silentlycontinue
```



#### Dependencies:  Run with `powershell`!
##### Description: The Get-AzDomainInfo script must exist in PathToAtomicsFolder\..\ExternalPayloads.
##### Check Prereq Commands:
```powershell
if (test-path "PathToAtomicsFolder\..\ExternalPayloads\Get-AzDomainInfo.ps1"){exit 0} else {exit 1}
```
##### Get Prereq Commands:
```powershell
New-Item -Type Directory "PathToAtomicsFolder\..\ExternalPayloads\" -ErrorAction Ignore -Force | Out-Null
invoke-webrequest "https://raw.githubusercontent.com/NetSPI/MicroBurst/c771c665a2c71f9c5ba474869cd1c211ebee68fd/Az/Get-AzDomainInfo.ps1" -outfile "PathToAtomicsFolder\..\ExternalPayloads\Get-AzDomainInfo.ps1"
```
##### Description: The Az module must be installed.
##### Check Prereq Commands:
```powershell
try {if (Get-InstalledModule -Name Az -ErrorAction SilentlyContinue) {exit 0} else {exit 1}} catch {exit 1}
```
##### Get Prereq Commands:
```powershell
Install-Module -Name Az -Force
```




<br/>
