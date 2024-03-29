---
tags: [T1006, atomic_test]
filename: "[[T1006 - Direct Volume Access]]"
---
# T1006 - Direct Volume Access

## Atomic Test #1 - Read volume boot sector via DOS device path (PowerShell)
This test uses PowerShell to open a handle on the drive volume via the `\\.\` [DOS device path specifier](https://docs.microsoft.com/en-us/dotnet/standard/io/file-path-formats#dos-device-paths) and perform direct access read of the first few bytes of the volume.
On success, a hex dump of the first 11 bytes of the volume is displayed.

For a NTFS volume, it should correspond to the following sequence ([NTFS partition boot sector](https://en.wikipedia.org/wiki/NTFS#Partition_Boot_Sector_(VBR))):
```
           00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F

00000000   EB 52 90 4E 54 46 53 20 20 20 20                 ëR?NTFS
```

**Supported Platforms:** Windows


**auto_generated_guid:** 88f6327e-51ec-4bbf-b2e8-3fea534eab8b





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| volume | Drive letter of the volume to access | string | C:|


#### Attack Commands: Run with `powershell`!  Elevation Required (e.g. root or admin) 


```powershell
$buffer = New-Object byte[] 11
$handle = New-Object IO.FileStream "\\.\#{volume}", 'Open', 'Read', 'ReadWrite'
$handle.Read($buffer, 0, $buffer.Length)
$handle.Close()
Format-Hex -InputObject $buffer
```






<br/>
