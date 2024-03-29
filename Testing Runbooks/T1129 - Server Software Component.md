---
tags: [T1129, atomic_test]
filename: "[[T1129 - Server Software Component]]"
---
# T1129 - Server Software Component

## Atomic Test #1 - ESXi - Install a custom VIB on an ESXi host
An adversary can maintain persistence within an ESXi host by installing malicious vSphere Installation Bundles (VIBs).
[Reference](https://www.mandiant.com/resources/blog/esxi-hypervisors-malware-persistence)

**Supported Platforms:** Windows


**auto_generated_guid:** 7f843046-abf2-443f-b880-07a83cf968ec





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| vm_host | Specify the host name of the ESXi Server | string | atomic.local|
| vm_user | Specify the privilege user account on ESXi Server | string | root|
| vm_pass | Specify the privilege user password on ESXi Server | string | pass|
| plink_file | Path to plink | path | PathToAtomicsFolder&#92;..&#92;ExternalPayloads&#92;plink.exe|
| pscp_file | Path to Pscp | path | PathToAtomicsFolder&#92;..&#92;ExternalPayloads&#92;pscp.exe|
| vib_install | Path to script with commands to install the vib | path | PathToAtomicsFolder&#92;..&#92;atomics&#92;T1129&#92;src&#92;esxi_vibinstall.txt|
| vib_remove | Path to script with commands to remove the vib | path | PathToAtomicsFolder&#92;..&#92;atomics&#92;T1129&#92;src&#92;esxi_vibremove.txt|
| vib_file | Path to the dummy vib | path | PathToAtomicsFolder&#92;..&#92;atomics&#92;T1129&#92;src&#92;atomicvibes.vib|


#### Attack Commands: Run with `command_prompt`! 


```cmd
#{pscp_file} -pw #{vm_pass} #{vib_file} #{vm_user}@#{vm_host}:/tmp
echo "" | "#{plink_file}" "#{vm_host}" -ssh  -l "#{vm_user}" -pw "#{vm_pass}" -m "#{vib_install}"
```

#### Cleanup Commands:
```cmd
echo "" | "#{plink_file}" "#{vm_host}" -ssh  -l "#{vm_user}" -pw "#{vm_pass}" -m "#{vib_remove}"
```



#### Dependencies:  Run with `powershell`!
##### Description: Check if plink and pscp are available.
##### Check Prereq Commands:
```powershell
if (Test-Path "#{plink_file}") {exit 0} else {exit 1}
if (Test-Path "#{pscp_file}") {exit 0} else {exit 1}
```
##### Get Prereq Commands:
```powershell
New-Item -Type Directory "PathToAtomicsFolder\..\ExternalPayloads\" -ErrorAction Ignore -Force | Out-Null
Invoke-WebRequest "https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe" -OutFile "PathToAtomicsFolder\..\ExternalPayloads\plink.exe"
Invoke-WebRequest "https://the.earth.li/~sgtatham/putty/latest/w64/pscp.exe" -OutFile "PathToAtomicsFolder\..\ExternalPayloads\pscp.exe"
```




<br/>
