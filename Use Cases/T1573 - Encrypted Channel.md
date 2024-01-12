---
created: 2020-03-16
last_modified: 2021-04-20
version: 1.0
tactics: Command and Control
url: https://attack.mitre.org/techniques/T1573
platforms: Linux, Windows, macOS
tags: [T1573, techniques, Command_and_Control]
---

## Encrypted Channel

### Description

Adversaries may employ a known encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol. Despite the use of a secure algorithm, these implementations may be vulnerable to reverse engineering if secret keys are encoded and/or generated within malware samples/configuration files.

### Detection

SSL/TLS inspection is one way of detecting command and control traffic within some encrypted communication channels.(Citation: SANS Decrypting SSL) SSL/TLS inspection does come with certain risks that should be considered before implementing to avoid potential security issues such as incomplete certificate validation.(Citation: SEI SSL Inspection Risks)

In general, analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Analyze packet contents to detect communications that do not follow the expected protocol behavior for the port that is being used.(Citation: University of Birmingham C2)

### Defenses Bypassed



### Data Sources

  - Network Traffic: Network Traffic Content
### Detection Rule

```query
tag: detection_rule
tag: T1573
```

### Rule Testing

```query
tag: atomic_test
tag: T1573
```
