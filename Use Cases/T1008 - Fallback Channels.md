---
created: 2017-05-31
last_modified: 2020-07-14
version: 1.0
tactics: Command and Control
url: https://attack.mitre.org/techniques/T1008
platforms: Linux, Windows, macOS
tags: [T1008, techniques, Command_and_Control]
---

## Fallback Channels

### Description

Adversaries may use fallback or alternate communication channels if the primary channel is compromised or inaccessible in order to maintain reliable command and control and to avoid data transfer thresholds.

### Detection

Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Analyze packet contents to detect communications that do not follow the expected protocol behavior for the port that is being used. (Citation: University of Birmingham C2)

### Defenses Bypassed



### Data Sources

  - Network Traffic: Network Connection Creation
  -  Network Traffic: Network Traffic Flow
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1008
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1008
```
