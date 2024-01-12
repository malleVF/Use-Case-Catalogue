---
created: 2017-05-31
last_modified: 2020-07-14
version: 1.0
tactics: Exfiltration
url: https://attack.mitre.org/techniques/T1030
platforms: Linux, Windows, macOS
tags: [T1030, techniques, Exfiltration]
---

## Data Transfer Size Limits

### Description

An adversary may exfiltrate data in fixed size chunks instead of whole files or limit packet sizes below certain thresholds. This approach may be used to avoid triggering network data transfer threshold alerts.

### Detection

Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). If a process maintains a long connection during which it consistently sends fixed size data packets or a process opens connections and sends fixed sized data packets at regular intervals, it may be performing an aggregate data transfer. Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Analyze packet contents to detect communications that do not follow the expected protocol behavior for the port that is being used. (Citation: University of Birmingham C2)

### Defenses Bypassed



### Data Sources

  - Network Traffic: Network Connection Creation
  -  Network Traffic: Network Traffic Flow
### Detection Rule

```query
tag: detection_rule
tag: T1030
```

### Rule Testing

```query
tag: atomic_test
tag: T1030
```
