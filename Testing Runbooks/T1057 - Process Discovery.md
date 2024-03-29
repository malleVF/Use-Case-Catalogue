---
tags: [T1057, atomic_test]
filename: "[[T1057 - Process Discovery]]"
---
# T1057 - Process Discovery

## Atomic Test #1 - Process Discovery - ps
Utilize ps to identify processes.

Upon successful execution, sh will execute ps and output to /tmp/loot.txt.

**Supported Platforms:** Linux, macOS


**auto_generated_guid:** 4ff64f0b-aaf2-4866-b39d-38d9791407cc





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| output_file | path of output file | path | /tmp/loot.txt|


#### Attack Commands: Run with `sh`! 


```sh
ps >> #{output_file}
ps aux >> #{output_file}
```

#### Cleanup Commands:
```sh
rm #{output_file}
```





<br/>
<br/>

## Atomic Test #2 - Process Discovery - tasklist
Utilize tasklist to identify processes.

Upon successful execution, cmd.exe will execute tasklist.exe to list processes. Output will be via stdout.

**Supported Platforms:** Windows


**auto_generated_guid:** c5806a4f-62b8-4900-980b-c7ec004e9908






#### Attack Commands: Run with `command_prompt`! 


```cmd
tasklist
```






<br/>
<br/>

## Atomic Test #3 - Process Discovery - Get-Process
Utilize Get-Process PowerShell cmdlet to identify processes.

Upon successful execution, powershell.exe will execute Get-Process to list processes. Output will be via stdout.

**Supported Platforms:** Windows


**auto_generated_guid:** 3b3809b6-a54b-4f5b-8aff-cb51f2e97b34






#### Attack Commands: Run with `powershell`! 


```powershell
Get-Process
```






<br/>
<br/>

## Atomic Test #4 - Process Discovery - get-wmiObject
Utilize get-wmiObject PowerShell cmdlet to identify processes.

Upon successful execution, powershell.exe will execute get-wmiObject to list processes. Output will be via stdout.

**Supported Platforms:** Windows


**auto_generated_guid:** b51239b4-0129-474f-a2b4-70f855b9f2c2






#### Attack Commands: Run with `powershell`! 


```powershell
get-wmiObject -class Win32_Process
```






<br/>
<br/>

## Atomic Test #5 - Process Discovery - wmic process
Utilize windows management instrumentation to identify processes.

Upon successful execution, WMIC will execute process to list processes. Output will be via stdout.

**Supported Platforms:** Windows


**auto_generated_guid:** 640cbf6d-659b-498b-ba53-f6dd1a1cc02c






#### Attack Commands: Run with `command_prompt`! 


```cmd
wmic process get /format:list
```






<br/>
<br/>

## Atomic Test #6 - Discover Specific Process - tasklist
Adversaries may use command line tools to discover specific processes in preparation of further attacks. 
Examples of this could be discovering the PID of lsass.exe to dump its memory or discovering whether specific security processes (e.g. AV or EDR) are running.

**Supported Platforms:** Windows


**auto_generated_guid:** 11ba69ee-902e-4a0f-b3b6-418aed7d7ddb





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| process_to_enumerate | Process name string to search for. | string | lsass|


#### Attack Commands: Run with `command_prompt`! 


```cmd
tasklist | findstr #{process_to_enumerate}
```






<br/>
