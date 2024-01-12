---
created: 2017-05-31
last_modified: 2020-03-15
version: 1.1
tactics: Command and Control
url: https://attack.mitre.org/techniques/T1001
platforms: Linux, Windows, macOS
tags: [T1001, techniques, Command_and_Control]
---

## Data Obfuscation

### Description

Adversaries may obfuscate command and control traffic to make it more difficult to detect. Command and control (C2) communications are hidden (but not necessarily encrypted) in an attempt to make the content more difficult to discover or decipher and to make the communication less conspicuous and hide commands from being seen. This encompasses many methods, such as adding junk data to protocol traffic, using steganography, or impersonating legitimate protocols. 

### Detection

Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Analyze packet contents to detect communications that do not follow the expected protocol behavior for the port that is being used. (Citation: University of Birmingham C2)

### Defenses Bypassed



### Data Sources

  - Network Traffic: Network Traffic Content
### Detection Rule

```query
tag: detection_rule
tag: T1001
```

### Rule Testing

```query
tag: atomic_test
tag: T1001
```
