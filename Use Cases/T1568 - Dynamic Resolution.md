---
created: 2020-03-10
last_modified: 2022-03-11
version: 1.0
tactics: Command and Control
url: https://attack.mitre.org/techniques/T1568
platforms: Linux, Windows, macOS
tags: [T1568, techniques, Command_and_Control]
---

## Dynamic Resolution

### Description

Adversaries may dynamically establish connections to command and control infrastructure to evade common detections and remediations. This may be achieved by using malware that shares a common algorithm with the infrastructure the adversary uses to receive the malware's communications. These calculations can be used to dynamically adjust parameters such as the domain name, IP address, or port number the malware uses for command and control.

Adversaries may use dynamic resolution for the purpose of [Fallback Channels](https://attack.mitre.org/techniques/T1008). When contact is lost with the primary command and control server malware may employ dynamic resolution as a means to reestablishing command and control.(Citation: Talos CCleanup 2017)(Citation: FireEye POSHSPY April 2017)(Citation: ESET Sednit 2017 Activity)

### Detection

Detecting dynamically generated C2 can be challenging due to the number of different algorithms, constantly evolving malware families, and the increasing complexity of the algorithms. There are multiple approaches to detecting a pseudo-randomly generated domain name, including using frequency analysis, Markov chains, entropy, proportion of dictionary words, ratio of vowels to other characters, and more (Citation: Data Driven Security DGA). CDN domains may trigger these detections due to the format of their domain names. In addition to detecting algorithm generated domains based on the name, another more general approach for detecting a suspicious domain is to check for recently registered names or for rarely visited domains.

### Defenses Bypassed



### Data Sources

  - Network Traffic: Network Connection Creation
  -  Network Traffic: Network Traffic Content
  -  Network Traffic: Network Traffic Flow
### Detection Rule

```query
tag: detection_rule
tag: T1568
```

### Rule Testing

```query
tag: atomic_test
tag: T1568
```
