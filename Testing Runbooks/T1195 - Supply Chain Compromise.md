---
tags: [T1195, atomic_test]
filename: "[[T1195 - Supply Chain Compromise]]"
---
# T1195 - Supply Chain Compromise

## Atomic Test #1 - Octopus Scanner Malware Open Source Supply Chain
This test simulates an adversary Octopus drop the RAT dropper ExplorerSync.db
[octopus-scanner-malware-open-source-supply-chain](https://securitylab.github.com/research/octopus-scanner-malware-open-source-supply-chain/)
[the-supreme-backdoor-factory](https://www.dfir.it/blog/2019/02/26/the-supreme-backdoor-factory/)

**Supported Platforms:** Windows


**auto_generated_guid:** 82a9f001-94c5-495e-9ed5-f530dbded5e2





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| rat_payload | RAT dropper ExplorerSync.db | path | $env:TEMP&#92;ExplorerSync.db|


#### Attack Commands: Run with `command_prompt`! 


```cmd
copy %temp%\ExplorerSync.db %temp%\..\Microsoft\ExplorerSync.db
schtasks /create /tn ExplorerSync /tr "javaw -jar %temp%\..\Microsoft\ExplorerSync.db" /sc MINUTE /f
```

#### Cleanup Commands:
```cmd
schtasks /delete /tn ExplorerSync /F 2>null
del %temp%\..\Microsoft\ExplorerSync.db 2>null
del %temp%\ExplorerSync.db 2>null
```



#### Dependencies:  Run with `powershell`!
##### Description: ExplorerSync.db must exist on disk at specified location (#{rat_payload})
##### Check Prereq Commands:
```powershell
if (Test-Path #{rat_payload}) {exit 0} else {exit 1}
```
##### Get Prereq Commands:
```powershell
Out-File -FilePath "#{rat_payload}"
```




<br/>
