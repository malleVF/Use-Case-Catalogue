---
tags: [T1091, atomic_test]
filename: "[[T1091 - Replication Through Removable Media]]"
---
# T1091 - Replication Through Removable Media

## Atomic Test #1 - USB Malware Spread Simulation
Simulates an adversary copying malware to all connected removable drives.

**Supported Platforms:** Windows


**auto_generated_guid:** d44b7297-622c-4be8-ad88-ec40d7563c75






#### Attack Commands: Run with `powershell`! 


```powershell
$RemovableDrives=@()
$RemovableDrives = Get-WmiObject -Class Win32_LogicalDisk -filter "drivetype=2" | select-object -expandproperty DeviceID
ForEach ($Drive in $RemovableDrives)
{
write-host "Removable Drive Found:" $Drive
New-Item -Path $Drive/T1091Test1.txt -ItemType "file" -Force -Value "T1091 Test 1 has created this file to simulate malware spread to removable drives."
}
```

#### Cleanup Commands:
```powershell
$RemovableDrives = Get-WmiObject -Class Win32_LogicalDisk -filter "drivetype=2" | select-object -expandproperty DeviceID
ForEach ($Drive in $RemovableDrives)
{
Remove-Item -Path $Drive\T1091Test1.txt -Force -ErrorAction Ignore
}
```





<br/>
