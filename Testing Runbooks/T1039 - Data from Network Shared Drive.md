---
tags: [T1039, atomic_test]
filename: "[[T1039 - Data from Network Shared Drive]]"
---
# T1039 - Data from Network Shared Drive

## Atomic Test #1 - Copy a sensitive File over Administrative share with copy
Copy from sensitive File from the c$ of another LAN computer with copy cmd
https://twitter.com/SBousseaden/status/1211636381086339073

**Supported Platforms:** Windows


**auto_generated_guid:** 6ed67921-1774-44ba-bac6-adb51ed60660





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| remote | Remote server name | string | 127.0.0.1|
| share_file | Remote Path to the file | path | Windows&#92;temp&#92;Easter_Bunny.password|
| local_file | Local name | string | Easter_egg.password|


#### Attack Commands: Run with `command_prompt`!  Elevation Required (e.g. root or admin) 


```cmd
copy \\#{remote}\C$\#{share_file} %TEMP%\#{local_file}
```

#### Cleanup Commands:
```cmd
del \\#{remote}\C$\#{share_file}
del %TEMP%\#{local_file}
```



#### Dependencies:  Run with `powershell`!
##### Description: Administrative share must exist on #{remote}
##### Check Prereq Commands:
```powershell
if (Test-Path "\\#{remote}\C$") {exit 0} else {exit 1}
```
##### Get Prereq Commands:
```powershell
Write-Host 'Please Enable "C$" share on #{remote}'
```
##### Description: "\\#{remote}\C$\#{share_file}" must exist on #{remote}
##### Check Prereq Commands:
```powershell
if (Test-Path "\\#{remote}\C$\#{share_file}") {exit 0} else {exit 1}
```
##### Get Prereq Commands:
```powershell
Out-File -FilePath "\\#{remote}\C$\#{share_file}"
```




<br/>
<br/>

## Atomic Test #2 - Copy a sensitive File over Administrative share with Powershell
Copy from sensitive File from the c$ of another LAN computer with powershell
https://twitter.com/SBousseaden/status/1211636381086339073

**Supported Platforms:** Windows


**auto_generated_guid:** 7762e120-5879-44ff-97f8-008b401b9a98





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| remote | Remote server name | string | 127.0.0.1|
| share_file | Remote Path to the file | path | Windows&#92;temp&#92;Easter_Bunny.password|
| local_file | Local name | string | Easter_egg.password|


#### Attack Commands: Run with `powershell`!  Elevation Required (e.g. root or admin) 


```powershell
copy-item -Path "\\#{remote}\C$\#{share_file}" -Destination "$Env:TEMP\#{local_file}"
```

#### Cleanup Commands:
```powershell
Remove-Item -Path "\\#{remote}\C$\#{share_file}"
Remove-Item -Path "$Env:TEMP\#{local_file}"
```



#### Dependencies:  Run with `powershell`!
##### Description: Administrative share must exist on #{remote}
##### Check Prereq Commands:
```powershell
if (Test-Path "\\#{remote}\C$") {exit 0} else {exit 1}
```
##### Get Prereq Commands:
```powershell
Write-Host 'Please Enable "C$" share on #{remote}'
```
##### Description: "\\#{remote}\C$\#{share_file}" must exist on #{remote}
##### Check Prereq Commands:
```powershell
if (Test-Path "\\#{remote}\C$\#{share_file}") {exit 0} else {exit 1}
```
##### Get Prereq Commands:
```powershell
Out-File -FilePath "\\#{remote}\C$\#{share_file}"
```




<br/>
