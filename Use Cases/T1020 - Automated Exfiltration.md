---
created: 2017-05-31
last_modified: 2022-04-19
version: 1.2
tactics: Exfiltration
url: https://attack.mitre.org/techniques/T1020
platforms: Linux, Network, Windows, macOS
tags: [T1020, techniques, Exfiltration]
---

## Automated Exfiltration

### Description

Adversaries may exfiltrate data, such as sensitive documents, through the use of automated processing after being gathered during Collection. 

When automated exfiltration is used, other exfiltration techniques likely apply as well to transfer the information out of the network, such as [Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041) and [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048).

### Detection

Monitor process file access patterns and network behavior. Unrecognized processes or scripts that appear to be traversing file systems and sending network traffic may be suspicious.

### Defenses Bypassed



### Data Sources

  - Command: Command Execution
  -  File: File Access
  -  Network Traffic: Network Connection Creation
  -  Network Traffic: Network Traffic Content
  -  Network Traffic: Network Traffic Flow
  -  Script: Script Execution
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1020
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1020
```
