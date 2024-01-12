---
created: 2020-03-11
last_modified: 2023-10-01
version: 1.3
tactics: Lateral Movement
url: https://attack.mitre.org/techniques/T1570
platforms: Linux, Windows, macOS
tags: [T1570, techniques, Lateral_Movement]
---

## Lateral Tool Transfer

### Description

Adversaries may transfer tools or other files between systems in a compromised environment. Once brought into the victim environment (i.e., [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)) files may then be copied from one system to another to stage adversary tools or other files over the course of an operation.

Adversaries may copy files between internal victim systems to support lateral movement using inherent file sharing protocols such as file sharing over [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002) to connected network shares or with authenticated connections via [Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001).(Citation: Unit42 LockerGoga 2019)

Files can also be transferred using native or otherwise present tools on the victim system, such as scp, rsync, curl, sftp, and [ftp](https://attack.mitre.org/software/S0095). In some cases, adversaries may be able to leverage [Web Service](https://attack.mitre.org/techniques/T1102)s such as Dropbox or OneDrive to copy files from one machine to another via shared, automatically synced folders.(Citation: Dropbox Malware Sync)

### Detection

Monitor for file creation and files transferred within a network using protocols such as SMB or FTP. Unusual processes with internal network connections creating files on-system may be suspicious. Consider monitoring for abnormal usage of utilities and command-line arguments that may be used in support of remote transfer of files. Considering monitoring for alike file hashes or characteristics (ex: filename) that are created on multiple hosts.

### Defenses Bypassed



### Data Sources

  - Command: Command Execution
  -  File: File Creation
  -  File: File Metadata
  -  Named Pipe: Named Pipe Metadata
  -  Network Share: Network Share Access
  -  Network Traffic: Network Traffic Content
  -  Network Traffic: Network Traffic Flow
  -  Process: Process Creation
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1570
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "Testing Runbooks" AND #T1570
```
