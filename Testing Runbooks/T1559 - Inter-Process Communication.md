---
tags: [T1559, atomic_test]
filename: "[[T1559 - Inter-Process Communication]]"
---
# T1559 - Inter-Process Communication

## Atomic Test #1 - Cobalt Strike Artifact Kit pipe
Uses the [Named Pipes Micro Emulation](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/master/micro_emulation_plans/src/named_pipes) executable from the Center for Threat Informed Defense to create a named pipe for inter-process communication.

The named pipe executable will pause for 30 seconds to allow the client and server to exchange a message through the pipe.

**Supported Platforms:** Windows


**auto_generated_guid:** bd13b9fc-b758-496a-b81a-397462f82c72






#### Attack Commands: Run with `command_prompt`! 


```cmd
"PathToAtomicsFolder\..\ExternalPayloads\build\namedpipes_executor.exe" --pipe 1
```




#### Dependencies:  Run with `powershell`!
##### Description: Named pipe executors must exist on disk
##### Check Prereq Commands:
```powershell
if ((Test-Path "PathToAtomicsFolder\..\ExternalPayloads\build\namedpipes_executor.exe") -and (Test-Path "PathToAtomicsFolder\..\ExternalPayloads\build\namedpipes_client.exe") -and (Test-Path "PathToAtomicsFolder\..\ExternalPayloads\build\namedpipes_server.exe")) {exit 0} else {exit 1}
```
##### Get Prereq Commands:
```powershell
New-Item -Type Directory "PathToAtomicsFolder\..\ExternalPayloads\" -ErrorAction ignore -Force | Out-Null
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (iwr "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-FetchFromZip.ps1" -UseBasicParsing)
$zipUrl  = "https://github.com/center-for-threat-informed-defense/adversary_emulation_library/raw/master/micro_emulation_plans/src/named_pipes/named_pipes.zip"
Invoke-FetchFromZip $zipUrl "*.exe" "PathToAtomicsFolder\..\ExternalPayloads"
```




<br/>
<br/>

## Atomic Test #2 - Cobalt Strike Lateral Movement (psexec_psh) pipe
Uses the [Named Pipes Micro Emulation](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/master/micro_emulation_plans/src/named_pipes) executable from the Center for Threat Informed Defense to create a named pipe for inter-process communication.

The named pipe executable will pause for 30 seconds to allow the client and server to exchange a message through the pipe.

**Supported Platforms:** Windows


**auto_generated_guid:** 830c8b6c-7a70-4f40-b975-8bbe74558acd






#### Attack Commands: Run with `command_prompt`! 


```cmd
"PathToAtomicsFolder\..\ExternalPayloads\build\namedpipes_executor.exe" --pipe 2
```




#### Dependencies:  Run with `powershell`!
##### Description: Named pipe executors must exist on disk
##### Check Prereq Commands:
```powershell
if ((Test-Path "PathToAtomicsFolder\..\ExternalPayloads\build\namedpipes_executor.exe") -and (Test-Path "PathToAtomicsFolder\..\ExternalPayloads\build\namedpipes_client.exe") -and (Test-Path "PathToAtomicsFolder\..\ExternalPayloads\build\namedpipes_server.exe")) {exit 0} else {exit 1}
```
##### Get Prereq Commands:
```powershell
New-Item -Type Directory "PathToAtomicsFolder\..\ExternalPayloads\" -ErrorAction ignore -Force | Out-Null
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (iwr "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-FetchFromZip.ps1" -UseBasicParsing)
$zipUrl  = "https://github.com/center-for-threat-informed-defense/adversary_emulation_library/raw/master/micro_emulation_plans/src/named_pipes/named_pipes.zip"
Invoke-FetchFromZip $zipUrl "*.exe" "PathToAtomicsFolder\..\ExternalPayloads"
```




<br/>
<br/>

## Atomic Test #3 - Cobalt Strike SSH (postex_ssh) pipe
Uses the [Named Pipes Micro Emulation](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/master/micro_emulation_plans/src/named_pipes) executable from the Center for Threat Informed Defense to create a named pipe for inter-process communication.

The named pipe executable will pause for 30 seconds to allow the client and server to exchange a message through the pipe.

**Supported Platforms:** Windows


**auto_generated_guid:** d1f72fa0-5bc2-4b4b-bd1e-43b6e8cfb2e6






#### Attack Commands: Run with `command_prompt`! 


```cmd
"PathToAtomicsFolder\..\ExternalPayloads\build\namedpipes_executor.exe" --pipe 3
```




#### Dependencies:  Run with `powershell`!
##### Description: Named pipe executors must exist on disk
##### Check Prereq Commands:
```powershell
if ((Test-Path "PathToAtomicsFolder\..\ExternalPayloads\build\namedpipes_executor.exe") -and (Test-Path "PathToAtomicsFolder\..\ExternalPayloads\build\namedpipes_client.exe") -and (Test-Path "PathToAtomicsFolder\..\ExternalPayloads\build\namedpipes_server.exe")) {exit 0} else {exit 1}
```
##### Get Prereq Commands:
```powershell
New-Item -Type Directory "PathToAtomicsFolder\..\ExternalPayloads\" -ErrorAction ignore -Force | Out-Null
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (iwr "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-FetchFromZip.ps1" -UseBasicParsing)
$zipUrl  = "https://github.com/center-for-threat-informed-defense/adversary_emulation_library/raw/master/micro_emulation_plans/src/named_pipes/named_pipes.zip"
Invoke-FetchFromZip $zipUrl "*.exe" "PathToAtomicsFolder\..\ExternalPayloads"
```




<br/>
<br/>

## Atomic Test #4 - Cobalt Strike post-exploitation pipe (4.2 and later)
Uses the [Named Pipes Micro Emulation](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/master/micro_emulation_plans/src/named_pipes) executable from the Center for Threat Informed Defense to create a named pipe for inter-process communication.

The named pipe executable will pause for 30 seconds to allow the client and server to exchange a message through the pipe.

**Supported Platforms:** Windows


**auto_generated_guid:** 7a48f482-246f-4aeb-9837-21c271ebf244






#### Attack Commands: Run with `command_prompt`! 


```cmd
"PathToAtomicsFolder\..\ExternalPayloads\build\namedpipes_executor.exe" --pipe 4
```




#### Dependencies:  Run with `powershell`!
##### Description: Named pipe executors must exist on disk
##### Check Prereq Commands:
```powershell
if ((Test-Path "PathToAtomicsFolder\..\ExternalPayloads\build\namedpipes_executor.exe") -and (Test-Path "PathToAtomicsFolder\..\ExternalPayloads\build\namedpipes_client.exe") -and (Test-Path "PathToAtomicsFolder\..\ExternalPayloads\build\namedpipes_server.exe")) {exit 0} else {exit 1}
```
##### Get Prereq Commands:
```powershell
New-Item -Type Directory "PathToAtomicsFolder\..\ExternalPayloads\" -ErrorAction ignore -Force | Out-Null
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (iwr "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-FetchFromZip.ps1" -UseBasicParsing)
$zipUrl  = "https://github.com/center-for-threat-informed-defense/adversary_emulation_library/raw/master/micro_emulation_plans/src/named_pipes/named_pipes.zip"
Invoke-FetchFromZip $zipUrl "*.exe" "PathToAtomicsFolder\..\ExternalPayloads"
```




<br/>
<br/>

## Atomic Test #5 - Cobalt Strike post-exploitation pipe (before 4.2)
Uses the [Named Pipes Micro Emulation](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/master/micro_emulation_plans/src/named_pipes) executable from the Center for Threat Informed Defense to create a named pipe for inter-process communication.

The named pipe executable will pause for 30 seconds to allow the client and server to exchange a message through the pipe.

**Supported Platforms:** Windows


**auto_generated_guid:** 8dbfc15c-527b-4ab0-a272-019f469d367f






#### Attack Commands: Run with `command_prompt`! 


```cmd
"PathToAtomicsFolder\..\ExternalPayloads\build\namedpipes_executor.exe" --pipe 5
```




#### Dependencies:  Run with `powershell`!
##### Description: Named pipe executors must exist on disk
##### Check Prereq Commands:
```powershell
if ((Test-Path "PathToAtomicsFolder\..\ExternalPayloads\build\namedpipes_executor.exe") -and (Test-Path "PathToAtomicsFolder\..\ExternalPayloads\build\namedpipes_client.exe") -and ("Test-Path PathToAtomicsFolder\..\ExternalPayloads\build\namedpipes_server.exe")) {exit 0} else {exit 1}
```
##### Get Prereq Commands:
```powershell
New-Item -Type Directory "PathToAtomicsFolder\..\ExternalPayloads\" -ErrorAction ignore -Force | Out-Null
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (iwr "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-FetchFromZip.ps1" -UseBasicParsing)
$zipUrl  = "https://github.com/center-for-threat-informed-defense/adversary_emulation_library/raw/master/micro_emulation_plans/src/named_pipes/named_pipes.zip"
Invoke-FetchFromZip $zipUrl "*.exe" "PathToAtomicsFolder\..\ExternalPayloads"
```




<br/>
