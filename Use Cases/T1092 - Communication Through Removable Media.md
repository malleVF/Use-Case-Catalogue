---
created: 2017-05-31
last_modified: 2020-07-14
version: 1.0
tactics: Command and Control
url: https://attack.mitre.org/techniques/T1092
platforms: Linux, Windows, macOS
tags: [T1092, techniques, Command_and_Control]
---

## Communication Through Removable Media

### Description

Adversaries can perform command and control between compromised hosts on potentially disconnected networks using removable media to transfer commands from system to system. Both systems would need to be compromised, with the likelihood that an Internet-connected system was compromised first and the second through lateral movement by [Replication Through Removable Media](https://attack.mitre.org/techniques/T1091). Commands and files would be relayed from the disconnected system to the Internet-connected system to which the adversary has direct access.

### Detection

Monitor file access on removable media. Detect processes that execute when removable media is mounted.

### Defenses Bypassed



### Data Sources

  - Drive: Drive Access
  -  Drive: Drive Creation
### Detection Rule

```query
tag: detection_rule
tag: T1092
```

### Rule Testing

```query
tag: atomic_test
tag: T1092
```
