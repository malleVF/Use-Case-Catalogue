---
created: 2017-05-31
last_modified: 2020-03-28
version: 1.1
tactics: Exfiltration
url: https://attack.mitre.org/techniques/T1029
platforms: Linux, Windows, macOS
tags: [T1029, techniques, Exfiltration]
---

## Scheduled Transfer

### Description

Adversaries may schedule data exfiltration to be performed only at certain times of day or at certain intervals. This could be done to blend traffic patterns with normal activity or availability.

When scheduled exfiltration is used, other exfiltration techniques likely apply as well to transfer the information out of the network, such as [Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041) or [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048).

### Detection

Monitor process file access patterns and network behavior. Unrecognized processes or scripts that appear to be traversing file systems and sending network traffic may be suspicious. Network connections to the same destination that occur at the same time of day for multiple days are suspicious.

### Defenses Bypassed



### Data Sources

  - Network Traffic: Network Connection Creation
  -  Network Traffic: Network Traffic Flow
### Detection Rule

```query
tag: detection_rule
tag: T1029
```

### Rule Testing

```query
tag: atomic_test
tag: T1029
```
