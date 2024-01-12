---
created: 2017-05-31
last_modified: 2023-04-07
version: 2.2
tactics: Exfiltration
url: https://attack.mitre.org/techniques/T1041
platforms: Linux, Windows, macOS
tags: [T1041, techniques, Exfiltration]
---

## Exfiltration Over C2 Channel

### Description

Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel using the same protocol as command and control communications.

### Detection

Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Analyze packet contents to detect communications that do not follow the expected protocol behavior for the port that is being used. (Citation: University of Birmingham C2)

### Defenses Bypassed



### Data Sources

  - Command: Command Execution
  -  File: File Access
  -  Network Traffic: Network Connection Creation
  -  Network Traffic: Network Traffic Content
  -  Network Traffic: Network Traffic Flow
### Detection Rule

```query
tag: detection_rule
tag: T1041
```

### Rule Testing

```query
tag: atomic_test
tag: T1041
```
