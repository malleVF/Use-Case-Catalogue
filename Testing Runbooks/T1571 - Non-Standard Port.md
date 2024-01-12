---
tags: [T1571, atomic_test]
filename: "[[T1571 - Non-Standard Port]]"
---
# T1571 - Non-Standard Port

## Atomic Test #1 - Testing usage of uncommonly used port with PowerShell
Testing uncommonly used port utilizing PowerShell. APT33 has been known to attempt telnet over port 8081. Upon execution, details about the successful
port check will be displayed.

**Supported Platforms:** Windows


**auto_generated_guid:** 21fe622f-8e53-4b31-ba83-6d333c2583f4





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| port | Specify uncommon port number | string | 8081|
| domain | Specify target hostname | string | google.com|


#### Attack Commands: Run with `powershell`! 


```powershell
Test-NetConnection -ComputerName #{domain} -port #{port}
```






<br/>
<br/>

## Atomic Test #2 - Testing usage of uncommonly used port
Testing uncommonly used port utilizing telnet.

**Supported Platforms:** Linux, macOS


**auto_generated_guid:** 5db21e1d-dd9c-4a50-b885-b1e748912767





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| port | Specify uncommon port number | string | 8081|
| domain | Specify target hostname | string | google.com|


#### Attack Commands: Run with `sh`! 


```sh
echo quit | telnet #{domain} #{port}
exit 0
```




#### Dependencies:  Run with `sh`!
##### Description: Requires telnet
##### Check Prereq Commands:
```sh
which telnet
```
##### Get Prereq Commands:
```sh
echo "please install telnet to run this test"; exit 1
```




<br/>
