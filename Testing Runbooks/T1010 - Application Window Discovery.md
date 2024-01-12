---
tags: [T1010, atomic_test]
filename: "[[T1010 - Application Window Discovery]]"
---
# T1010 - Application Window Discovery

## Atomic Test #1 - List Process Main Windows - C# .NET
Compiles and executes C# code to list main window titles associated with each process.

Upon successful execution, powershell will download the .cs from the Atomic Red Team repo, and cmd.exe will compile and execute T1010.exe. Upon T1010.exe execution, expected output will be via stdout.

**Supported Platforms:** Windows


**auto_generated_guid:** fe94a1c3-3e22-4dc9-9fdf-3a8bdbc10dc4





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| input_source_code | Path to source of C# code | path | PathToAtomicsFolder&#92;T1010&#92;src&#92;T1010.cs|
| output_file_name | Name of output binary | string | %TEMP%&#92;T1010.exe|


#### Attack Commands: Run with `command_prompt`! 


```cmd
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe -out:#{output_file_name} "#{input_source_code}"
#{output_file_name}
```

#### Cleanup Commands:
```cmd
del /f /q /s #{output_file_name} >nul 2>&1
```



#### Dependencies:  Run with `powershell`!
##### Description: T1010.cs must exist on disk at specified location (#{input_source_code})
##### Check Prereq Commands:
```powershell
if (Test-Path "#{input_source_code}") {exit 0} else {exit 1}
```
##### Get Prereq Commands:
```powershell
New-Item -Type Directory (split-path "#{input_source_code}") -ErrorAction ignore | Out-Null
Invoke-WebRequest https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1010/src/T1010.cs -OutFile "#{input_source_code}"
```




<br/>
