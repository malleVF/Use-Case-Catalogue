---
created: 2019-06-28
last_modified: 2022-10-19
version: 1.4
tactics: Persistence
url: https://attack.mitre.org/techniques/T1505
platforms: Linux, Network, Windows, macOS
tags: [T1505, techniques, Persistence]
---

## Server Software Component

### Description

Adversaries may abuse legitimate extensible development features of servers to establish persistent access to systems. Enterprise server applications may include features that allow developers to write and install software or scripts to extend the functionality of the main application. Adversaries may install malicious components to extend and abuse server applications.(Citation: volexity_0day_sophos_FW)

### Detection

Consider monitoring application logs for abnormal behavior that may indicate suspicious installation of application software components. Consider monitoring file locations associated with the installation of new application software components such as paths from which applications typically load such extensible components.

Process monitoring may be used to detect servers components that perform suspicious actions such as running cmd.exe or accessing files. Log authentication attempts to the server and any unusual traffic patterns to or from the server and internal network. (Citation: US-CERT Alert TA15-314A Web Shells) 

### Defenses Bypassed



### Data Sources

  - Application Log: Application Log Content
  -  File: File Creation
  -  File: File Modification
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
FROM "Detection Rules" AND #T1505
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "Testing Runbooks" AND #T1505
```
