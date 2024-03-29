---
tags: [T1654, atomic_test]
filename: "[[T1654 - Log Enumeration]]"
---
# T1654 - Log Enumeration

## Atomic Test #1 - Get-EventLog To Enumerate Windows Security Log
Uses the built-in PowerShell commandlet Get-EventLog to search for 'SYSTEM' keyword and saves results to a text file.

This technique was observed in a [TheDFIRReport case](https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware/) 
where the threat actor enumerated the Windows Security audit log to determine user accounts and associated IPv4 addresses.

Successful execution will save matching log events to the users temp folder.

**Supported Platforms:** Windows


**auto_generated_guid:** a9030b20-dd4b-4405-875e-3462c6078fdc






#### Attack Commands: Run with `powershell`!  Elevation Required (e.g. root or admin) 


```powershell
powershell -c "get-eventlog 'Security' | where {$_.Message -like '*SYSTEM*'} | export-csv $env:temp\T1654_events.txt"
```

#### Cleanup Commands:
```powershell
powershell -c "remove-item $env:temp\T1654_events.txt -ErrorAction Ignore"
```





<br/>
