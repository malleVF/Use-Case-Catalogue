---
tags: [T1072, atomic_test]
filename: "[[T1072 - Software Deployment Tools]]"
---
# T1072 - Software Deployment Tools

## Atomic Test #1 - Radmin Viewer Utility
An adversary may use Radmin Viewer Utility to remotely control Windows device, this will start the radmin console.

**Supported Platforms:** Windows


**auto_generated_guid:** b4988cad-6ed2-434d-ace5-ea2670782129





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| radmin_installer | Radmin Viewer installer | path | RadminViewer.msi|
| radmin_exe | The radmin.exe executable from RadminViewer.msi | path | Radmin Viewer 3/Radmin.exe|


#### Attack Commands: Run with `command_prompt`!  Elevation Required (e.g. root or admin) 


```cmd
"%PROGRAMFILES(x86)%/#{radmin_exe}"
```




#### Dependencies:  Run with `powershell`!
##### Description: Radmin Viewer Utility must be installed at specified location (#{radmin_exe})
##### Check Prereq Commands:
```powershell
if (Test-Path "${env:ProgramFiles(x86)}/#{radmin_exe}") {exit 0} else {exit 1}
```
##### Get Prereq Commands:
```powershell
Write-Host Downloading radmin installer
New-Item -Type Directory "PathToAtomicsFolder\..\ExternalPayloads\" -ErrorAction Ignore -Force | Out-Null
Invoke-WebRequest "https://www.radmin.com/download/Radmin_Viewer_3.5.2.1_EN.msi" -OutFile "PathToAtomicsFolder\..\ExternalPayloads\#{radmin_installer}"
Write-Host Install Radmin
Start-Process msiexec  -Wait -ArgumentList /i , "PathToAtomicsFolder\..\ExternalPayloads\#{radmin_installer}", /qn
```




<br/>
<br/>

## Atomic Test #2 - PDQ Deploy RAT
An adversary may use PDQ Deploy Software to deploy the Remote Adminstartion Tool, this will start the PDQ console.

**Supported Platforms:** Windows


**auto_generated_guid:** e447b83b-a698-4feb-bed1-a7aaf45c3443





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| PDQ_Deploy_installer | PDQ Deploy Install | path | PDQDeploysetup.exe|
| PDQ_Deploy_exe | The PDQDeployConsole.exe executable from PDQDeploysetup.exe | path | Admin Arsenal/PDQ Deploy/PDQDeployConsole.exe|


#### Attack Commands: Run with `command_prompt`!  Elevation Required (e.g. root or admin) 


```cmd
"%PROGRAMFILES(x86)%/#{PDQ_Deploy_exe}"
```




#### Dependencies:  Run with `powershell`!
##### Description: PDQ Deploy will be installed at specified location (#{PDQ_Deploy_exe})
##### Check Prereq Commands:
```powershell
if (Test-Path "${env:ProgramFiles(x86)}/#{PDQ_Deploy_exe}") {exit 0} else {exit 1}
```
##### Get Prereq Commands:
```powershell
Write-Host Downloading PDQ Deploy installer
New-Item -Type Directory "PathToAtomicsFolder\..\ExternalPayloads\" -ErrorAction Ignore -Force | Out-Null
Invoke-WebRequest "https://download.pdq.com/release/19/Deploy_19.3.350.0.exe" -OutFile "PathToAtomicsFolder\..\ExternalPayloads\#{PDQ_Deploy_installer}"
Write-Host Install PDQ Deploy
Start-Process "PathToAtomicsFolder\..\ExternalPayloads\#{PDQ_Deploy_installer}" -Wait -ArgumentList "/s"
```




<br/>
