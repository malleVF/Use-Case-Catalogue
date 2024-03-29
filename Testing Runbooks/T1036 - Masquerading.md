---
tags: [T1036, atomic_test]
filename: "[[T1036 - Masquerading]]"
---
# T1036 - Masquerading

## Atomic Test #1 - System File Copied to Unusual Location
It may be suspicious seeing a file copy of an EXE in System32 or SysWOW64 to a non-system directory or executing from a non-system directory.

**Supported Platforms:** Windows


**auto_generated_guid:** 51005ac7-52e2-45e0-bdab-d17c6d4916cd






#### Attack Commands: Run with `powershell`! 


```powershell
copy-item "$env:windir\System32\cmd.exe" -destination "$env:allusersprofile\cmd.exe"
start-process "$env:allusersprofile\cmd.exe"
sleep -s 5 
stop-process -name "cmd" | out-null
```

#### Cleanup Commands:
```powershell
remove-item "$env:allusersprofile\cmd.exe" -force -erroraction silentlycontinue
```





<br/>
<br/>

## Atomic Test #2 - Malware Masquerading and Execution from Zip File
When the file is unzipped and the README.cmd file opened, it executes and changes the .pdf to .dll and executes the dll. This is a BazaLoader technique [as reported here](https://twitter.com/ffforward/status/1481672378639912960)

**Supported Platforms:** Windows


**auto_generated_guid:** 4449c89b-ec82-43a4-89c1-91e2f1abeecc





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| url | Location of zip file | url | https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1036/bin/T1036.zip|


#### Attack Commands: Run with `powershell`! 


```powershell
Expand-Archive -Path "PathToAtomicsFolder\..\ExternalPayloads\T1036.zip" -DestinationPath "$env:userprofile\Downloads\T1036" -Force
cd "$env:userprofile\Downloads\T1036"
cmd /c "$env:userprofile\Downloads\T1036\README.cmd" >$null 2>$null
```

#### Cleanup Commands:
```powershell
taskkill /IM Calculator.exe /f >$null 2>$null
Remove-Item "$env:userprofile\Downloads\T1036" -recurse -ErrorAction Ignore
```



#### Dependencies:  Run with `powershell`!
##### Description: Zip file must be present.
##### Check Prereq Commands:
```powershell
if (Test-Path "PathToAtomicsFolder\..\ExternalPayloads\T1036.zip") {exit 0} else {exit 1}
```
##### Get Prereq Commands:
```powershell
New-Item -Type Directory "PathToAtomicsFolder\..\ExternalPayloads\" -ErrorAction ignore -Force | Out-Null
Invoke-WebRequest #{url} -OutFile "PathToAtomicsFolder\..\ExternalPayloads\T1036.zip"
```




<br/>
