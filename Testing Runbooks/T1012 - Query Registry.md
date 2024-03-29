---
tags: [T1012, atomic_test]
filename: "[[T1012 - Query Registry]]"
---
# T1012 - Query Registry

## Atomic Test #1 - Query Registry
Query Windows Registry.
Upon successful execution, cmd.exe will perform multiple reg queries. Some will succeed and others will fail (dependent upon OS).
References:
https://blog.cylance.com/windows-registry-persistence-part-2-the-run-keys-and-search-order
https://blog.cylance.com/windows-registry-persistence-part-1-introduction-attack-phases-and-windows-services
http://www.handgrep.se/repository/cheatsheets/postexploitation/WindowsPost-Exploitation.pdf
https://www.offensive-security.com/wp-content/uploads/2015/04/wp.Registry_Quick_Find_Chart.en_us.pdf

**Supported Platforms:** Windows


**auto_generated_guid:** 8f7578c4-9863-4d83-875c-a565573bbdf0






#### Attack Commands: Run with `command_prompt`!  Elevation Required (e.g. root or admin) 


```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify"
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit"
reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell"
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell"
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
reg query HKLM\system\currentcontrolset\services /s | findstr ImagePath 2>nul | findstr /Ri ".*\.sys$"
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup"
```






<br/>
<br/>

## Atomic Test #2 - Query Registry with Powershell cmdlets
Query Windows Registry with Powershell cmdlets, i.e., Get-Item and Get-ChildItem. The results from above can also be achieved with Get-Item and Get-ChildItem.
Unlike using "reg query" which then executes reg.exe, using cmdlets won't generate new processes, which may evade detection systems monitoring process generation.

**Supported Platforms:** Windows


**auto_generated_guid:** 0434d081-bb32-42ce-bcbb-3548e4f2628f






#### Attack Commands: Run with `powershell`!  Elevation Required (e.g. root or admin) 


```powershell
Get-Item -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
Get-ChildItem -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\" | findstr Windows
Get-Item -Path "HKLM:Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
Get-Item -Path "HKCU:Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
Get-Item -Path "HKLM:Software\Microsoft\Windows\CurrentVersion\RunServices"
Get-Item -Path "HKCU:Software\Microsoft\Windows\CurrentVersion\RunServices"
Get-Item -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify"
Get-Item -Path "HKLM:Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit"
Get-Item -Path "HKCU:Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell"
Get-Item -Path "HKLM:Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell"
Get-Item -Path "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad"
Get-Item -Path "HKLM:Software\Microsoft\Windows\CurrentVersion\RunOnce"
Get-Item -Path "HKLM:Software\Microsoft\Windows\CurrentVersion\RunOnceEx"
Get-Item -Path "HKLM:Software\Microsoft\Windows\CurrentVersion\Run"
Get-Item -Path "HKCU:Software\Microsoft\Windows\CurrentVersion\Run"
Get-Item -Path "HKCU:Software\Microsoft\Windows\CurrentVersion\RunOnce"
Get-Item -Path "HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
Get-Item -Path "HKCU:Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
Get-ChildItem -Path "HKLM:system\currentcontrolset\services" 
Get-Item -Path "HKLM:Software\Microsoft\Windows\CurrentVersion\Run"
Get-Item -Path "HKLM:SYSTEM\CurrentControlSet\Control\SafeBoot"
Get-ChildItem -Path "HKLM:SOFTWARE\Microsoft\Active Setup\Installed Components"
Get-ChildItem -Path "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup"
```






<br/>
<br/>

## Atomic Test #3 - Enumerate COM Objects in Registry with Powershell
This test is designed to enumerate the COM objects listed in HKCR, then output their methods and CLSIDs to a text file.
An adversary could then use this information to identify COM objects that might be vulnerable to abuse, such as using them to spawn arbitrary processes. 
See: https://www.mandiant.com/resources/hunting-com-objects

**Supported Platforms:** Windows


**auto_generated_guid:** 0d80d088-a84c-4353-af1a-fc8b439f1564





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| output_file | File to output list of COM objects to | string | $env:temp&#92;T1592.002Test1.txt|


#### Attack Commands: Run with `powershell`! 


```powershell
New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR
Get-ChildItem -Path HKCR:\CLSID -Name | Select -Skip 1 > $env:temp\clsids.txt
ForEach($CLSID in Get-Content "$env:temp\clsids.txt")
{try{write-output "$($Position)-$($CLSID)"
write-output "------------"| out-file #{output_file} -append
write-output $($CLSID)| out-file #{output_file} -append
$handle=[activator]::CreateInstance([type]::GetTypeFromCLSID($CLSID))
$handle | get-member -erroraction silentlycontinue | out-file #{output_file} -append
$position += 1} catch{}}
```

#### Cleanup Commands:
```powershell
remove-item #{output_file} -force -erroraction silentlycontinue
remove-item $env:temp\clsids.txt -force -erroraction silentlycontinue
```





<br/>
