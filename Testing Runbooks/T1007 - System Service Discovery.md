---
tags: [T1007, atomic_test]
filename: "[[T1007 - System Service Discovery]]"
---
# T1007 - System Service Discovery

## Atomic Test #1 - System Service Discovery
Identify system services.

Upon successful execution, cmd.exe will execute service commands with expected result to stdout.

**Supported Platforms:** Windows


**auto_generated_guid:** 89676ba1-b1f8-47ee-b940-2e1a113ebc71






#### Attack Commands: Run with `command_prompt`!  Elevation Required (e.g. root or admin) 


```cmd
tasklist.exe
sc query
sc query state= all
```






<br/>
<br/>

## Atomic Test #2 - System Service Discovery - net.exe
Enumerates started system services using net.exe and writes them to a file. This technique has been used by multiple threat actors.

Upon successful execution, net.exe will run from cmd.exe that queries services. Expected output is to a txt file in in the temp directory called service-list.txt.

**Supported Platforms:** Windows


**auto_generated_guid:** 5f864a3f-8ce9-45c0-812c-bdf7d8aeacc3





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| output_file | Path of file to hold net.exe output | path | %temp%&#92;service-list.txt|


#### Attack Commands: Run with `command_prompt`! 


```cmd
net.exe start >> #{output_file}
```

#### Cleanup Commands:
```cmd
del /f /q /s #{output_file} >nul 2>&1
```





<br/>
<br/>

## Atomic Test #3 - System Service Discovery - systemctl/service
Enumerates system service using systemctl/service

**Supported Platforms:** Linux


**auto_generated_guid:** f4b26bce-4c2c-46c0-bcc5-fce062d38bef






#### Attack Commands: Run with `bash`! 


```bash
if [ "$(uname)" = 'FreeBSD' ]; then service -e; else systemctl --type=service; fi;
```






<br/>
