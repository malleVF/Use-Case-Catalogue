---
created: 2017-05-31
last_modified: 2023-08-11
version: 1.4
tactics: Collection
url: https://attack.mitre.org/techniques/T1039
platforms: Linux, Windows, macOS
tags: [T1039, techniques, Collection]
---

## Data from Network Shared Drive

### Description

Adversaries may search network shares on computers they have compromised to find files of interest. Sensitive data can be collected from remote systems via shared network drives (host shared directory, network file server, etc.) that are accessible from the current system prior to Exfiltration. Interactive command shells may be in use, and common functionality within [cmd](https://attack.mitre.org/software/S0106) may be used to gather information.

### Detection

Monitor processes and command-line arguments for actions that could be taken to collect files from a network share. Remote access tools with built-in features may interact directly with the Windows API to gather data. Data may also be acquired through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).

### Defenses Bypassed



### Data Sources

  - Command: Command Execution
  -  File: File Access
  -  Network Share: Network Share Access
  -  Network Traffic: Network Connection Creation
  -  Network Traffic: Network Traffic Content
  -  Network Traffic: Network Traffic Flow
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1039
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1039
```
