---
tags: [T1070, atomic_test]
filename: "[[T1070 - Indicator Removal on Host]]"
---
# T1070 - Indicator Removal on Host

## Atomic Test #1 - Indicator Removal using FSUtil
Manages the update sequence number (USN) change journal, which provides a persistent log of all changes made to files on the volume. Upon execution, no output
will be displayed. More information about fsutil can be found at https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn

**Supported Platforms:** Windows


**auto_generated_guid:** b4115c7a-0e92-47f0-a61e-17e7218b2435






#### Attack Commands: Run with `command_prompt`!  Elevation Required (e.g. root or admin) 


```cmd
fsutil usn deletejournal /D C:
```

#### Cleanup Commands:
```cmd
fsutil usn createjournal m=1000 a=100 c:
```





<br/>
<br/>

## Atomic Test #2 - Indicator Manipulation using FSUtil
Finds a file by user name (if Disk Quotas are enabled), queries allocated ranges for a file, sets a file's short name, sets a file's valid data length, sets zero data for a file, or creates a new file. Upon execution, no output
will be displayed. More information about fsutil can be found at https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-file
- https://tria.ge/230601-x8x6bsgb24/behavioral2

**Supported Platforms:** Windows


**auto_generated_guid:** 96e86706-6afd-45b6-95d6-108d23eaf2e9





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| file_to_manipulate | Path of file to manipulate | path | PathToAtomicsFolder&#92;..&#92;ExternalPayloads&#92;T1070-2.txt|
| file_data_length | Data length to setzero | integer | 10|


#### Attack Commands: Run with `powershell`! 


```powershell
if (-not (Test-Path "#{file_to_manipulate}")) { New-Item "#{file_to_manipulate}" -Force } 
echo "1234567890" > "#{file_to_manipulate}"
fsutil  file setZeroData offset=0 length=#{file_data_length} "#{file_to_manipulate}"
```

#### Cleanup Commands:
```powershell
rm "#{file_to_manipulate}"
```





<br/>
