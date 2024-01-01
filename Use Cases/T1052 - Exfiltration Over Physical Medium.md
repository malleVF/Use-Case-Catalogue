---
created: 2017-05-31
last_modified: 2021-10-15
version: 1.2
tactics: Exfiltration
url: https://attack.mitre.org/techniques/T1052
platforms: Linux, Windows, macOS
tags: [T1052, techniques, Exfiltration]
---

## Exfiltration Over Physical Medium

### Description

Adversaries may attempt to exfiltrate data via a physical medium, such as a removable drive. In certain circumstances, such as an air-gapped network compromise, exfiltration could occur via a physical medium or device introduced by a user. Such media could be an external hard drive, USB drive, cellular phone, MP3 player, or other removable storage and processing device. The physical medium or device could be used as the final exfiltration point or to hop between otherwise disconnected systems.

### Detection

Monitor file access on removable media. Detect processes that execute when removable media are mounted.

### Defenses Bypassed



### Data Sources

  - Command: Command Execution
  -  Drive: Drive Creation
  -  File: File Access
  -  Process: Process Creation
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1052
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1052
```
