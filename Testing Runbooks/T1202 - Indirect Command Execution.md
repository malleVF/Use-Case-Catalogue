---
tags: [T1202, atomic_test]
filename: "[[T1202 - Indirect Command Execution]]"
---
# T1202 - Indirect Command Execution

## Atomic Test #1 - Indirect Command Execution - pcalua.exe
The Program Compatibility Assistant (pcalua.exe) may invoke the execution of programs and commands from a Command-Line Interface.
[Reference](https://twitter.com/KyleHanslovan/status/912659279806640128)
Upon execution, calc.exe should open

**Supported Platforms:** Windows


**auto_generated_guid:** cecfea7a-5f03-4cdd-8bc8-6f7c22862440





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| payload_path | Path to payload | path | C:&#92;Windows&#92;System32&#92;calc.exe|
| process | Process to execute | string | calc.exe|


#### Attack Commands: Run with `command_prompt`! 


```cmd
pcalua.exe -a #{process}
pcalua.exe -a #{payload_path}
```






<br/>
<br/>

## Atomic Test #2 - Indirect Command Execution - forfiles.exe
forfiles.exe may invoke the execution of programs and commands from a Command-Line Interface.
[Reference](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Forfiles.yml)
"This is basically saying for each occurrence of notepad.exe in c:\windows\system32 run calc.exe"
Upon execution calc.exe will be opened.

**Supported Platforms:** Windows


**auto_generated_guid:** 8b34a448-40d9-4fc3-a8c8-4bb286faf7dc





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| process | Process to execute | string | calc.exe|


#### Attack Commands: Run with `command_prompt`! 


```cmd
forfiles /p c:\windows\system32 /m notepad.exe /c #{process}
```






<br/>
<br/>

## Atomic Test #3 - Indirect Command Execution - conhost.exe
conhost.exe refers to a host process for the console window. It provide an interface between command prompt and Windows explorer.
Executing it through command line can create process ancestry anomalies
[Reference] (http://www.hexacorn.com/blog/2020/05/25/how-to-con-your-host/)

**Supported Platforms:** Windows


**auto_generated_guid:** cf3391e0-b482-4b02-87fc-ca8362269b29





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| process | Process to execute | string | notepad.exe|


#### Attack Commands: Run with `command_prompt`! 


```cmd
conhost.exe "#{process}"
```






<br/>
