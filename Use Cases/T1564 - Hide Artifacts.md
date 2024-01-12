---
created: 2020-02-26
last_modified: 2022-03-25
version: 1.1
tactics: Defense Evasion
url: https://attack.mitre.org/techniques/T1564
platforms: Linux, Office 365, Windows, macOS
tags: [T1564, techniques, Defense_Evasion]
---

## Hide Artifacts

### Description

Adversaries may attempt to hide artifacts associated with their behaviors to evade detection. Operating systems may have features to hide various artifacts, such as important system files and administrative task execution, to avoid disrupting user work environments and prevent users from changing files or features on the system. Adversaries may abuse these features to hide artifacts such as files, directories, user accounts, or other system activity to evade detection.(Citation: Sofacy Komplex Trojan)(Citation: Cybereason OSX Pirrit)(Citation: MalwareBytes ADS July 2015)

Adversaries may also attempt to hide artifacts associated with malicious behavior by creating computing regions that are isolated from common security instrumentation, such as through the use of virtualization technology.(Citation: Sophos Ragnar May 2020)

### Detection

Monitor files, processes, and command-line arguments for actions indicative of hidden artifacts. Monitor event and authentication logs for records of hidden artifacts being used. Monitor the file system and shell commands for hidden attribute usage.

### Defenses Bypassed



### Data Sources

  - Application Log: Application Log Content
  -  Command: Command Execution
  -  File: File Creation
  -  File: File Metadata
  -  File: File Modification
  -  Firmware: Firmware Modification
  -  Process: OS API Execution
  -  Process: Process Creation
  -  Script: Script Execution
  -  Service: Service Creation
  -  User Account: User Account Creation
  -  User Account: User Account Metadata
  -  Windows Registry: Windows Registry Key Modification
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1564
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "Testing Runbooks" AND #T1564
```
