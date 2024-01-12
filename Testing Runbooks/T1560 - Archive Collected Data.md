---
tags: [T1560, atomic_test]
filename: "[[T1560 - Archive Collected Data]]"
---
# T1560 - Archive Collected Data

## Atomic Test #1 - Compress Data for Exfiltration With PowerShell
An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration.
When the test completes you should find the files from the $env:USERPROFILE directory compressed in a file called T1560-data-ps.zip in the $env:USERPROFILE directory

**Supported Platforms:** Windows


**auto_generated_guid:** 41410c60-614d-4b9d-b66e-b0192dd9c597





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| input_file | Path that should be compressed into our output file | path | $env:USERPROFILE|
| output_file | Path where resulting compressed data should be placed | path | $env:USERPROFILE&#92;T1560-data-ps.zip|


#### Attack Commands: Run with `powershell`! 


```powershell
dir #{input_file} -Recurse | Compress-Archive -DestinationPath #{output_file}
```

#### Cleanup Commands:
```powershell
Remove-Item -path #{output_file} -ErrorAction Ignore
```





<br/>
