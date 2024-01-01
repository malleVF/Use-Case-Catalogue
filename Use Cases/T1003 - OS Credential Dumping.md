---
created: 2017-05-31
last_modified: 2022-03-08
version: 2.1
tactics: Credential Access
url: https://attack.mitre.org/techniques/T1003
platforms: Linux, Windows, macOS
tags: [T1003, techniques, Credential_Access]
---

## OS Credential Dumping

### Description

Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password, from the operating system and software. Credentials can then be used to perform [Lateral Movement](https://attack.mitre.org/tactics/TA0008) and access restricted information.

Several of the tools mentioned in associated sub-techniques may be used by both adversaries and professional security testers. Additional custom tools likely exist as well.


### Detection

### Windows
Monitor for unexpected processes interacting with lsass.exe.(Citation: Medium Detecting Attempts to Steal Passwords from Memory) Common credential dumpers such as [Mimikatz](https://attack.mitre.org/software/S0002) access the LSA Subsystem Service (LSASS) process by opening the process, locating the LSA secrets key, and decrypting the sections in memory where credential details are stored. Credential dumpers may also use methods for reflective [Process Injection](https://attack.mitre.org/techniques/T1055) to reduce potential indicators of malicious activity.

Hash dumpers open the Security Accounts Manager (SAM) on the local file system (%SystemRoot%/system32/config/SAM) or create a dump of the Registry SAM key to access stored account password hashes. Some hash dumpers will open the local file system as a device and parse to the SAM table to avoid file access defenses. Others will make an in-memory copy of the SAM table before reading hashes. Detection of compromised [Valid Accounts](https://attack.mitre.org/techniques/T1078) in-use by adversaries may help as well. 

On Windows 8.1 and Windows Server 2012 R2, monitor Windows Logs for LSASS.exe creation to verify that LSASS started as a protected process.

Monitor processes and command-line arguments for program execution that may be indicative of credential dumping. Remote access tools may contain built-in features or incorporate existing tools like [Mimikatz](https://attack.mitre.org/software/S0002). [PowerShell](https://attack.mitre.org/techniques/T1059/001) scripts also exist that contain credential dumping functionality, such as PowerSploit's Invoke-Mimikatz module, (Citation: Powersploit) which may require additional logging features to be configured in the operating system to collect necessary information for analysis.

Monitor domain controller logs for replication requests and other unscheduled activity possibly associated with DCSync. (Citation: Microsoft DRSR Dec 2017) (Citation: Microsoft GetNCCChanges) (Citation: Samba DRSUAPI) Note: Domain controllers may not log replication requests originating from the default domain controller account. (Citation: Harmj0y DCSync Sept 2015). Also monitor for network protocols  (Citation: Microsoft DRSR Dec 2017) (Citation: Microsoft NRPC Dec 2017) and other replication requests (Citation: Microsoft SAMR) from IPs not associated with known domain controllers. (Citation: AdSecurity DCSync Sept 2015)

### Linux
To obtain the passwords and hashes stored in memory, processes must open a maps file in the /proc filesystem for the process being analyzed. This file is stored under the path <code>/proc/<pid>/maps</code>, where the <code><pid></code> directory is the unique pid of the program being interrogated for such authentication data. The AuditD monitoring tool, which ships stock in many Linux distributions, can be used to watch for hostile processes opening this file in the proc file system, alerting on the pid, process name, and arguments of such programs.

### Defenses Bypassed



### Data Sources

  - Active Directory: Active Directory Object Access
  -  Command: Command Execution
  -  File: File Access
  -  Network Traffic: Network Traffic Content
  -  Network Traffic: Network Traffic Flow
  -  Process: OS API Execution
  -  Process: Process Access
  -  Process: Process Creation
  -  Windows Registry: Windows Registry Key Access
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1003
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1003
```
