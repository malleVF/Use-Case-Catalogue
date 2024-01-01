---
created: 2018-04-18
last_modified: 2023-03-30
version: 1.6
tactics: Initial Access
url: https://attack.mitre.org/techniques/T1200
platforms: Linux, Windows, macOS
tags: [T1200, techniques, Initial_Access]
---

## Hardware Additions

### Description

Adversaries may introduce computer accessories, networking hardware, or other computing devices into a system or network that can be used as a vector to gain access. Rather than just connecting and distributing payloads via removable storage (i.e. [Replication Through Removable Media](https://attack.mitre.org/techniques/T1091)), more robust hardware additions can be used to introduce new functionalities and/or features into a system that can then be abused.

While public references of usage by threat actors are scarce, many red teams/penetration testers leverage hardware additions for initial access. Commercial and open source products can be leveraged with capabilities such as passive network tapping, network traffic modification (i.e. [Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557)), keystroke injection, kernel memory reading via DMA, addition of new wireless access to an existing network, and others.(Citation: Ossmann Star Feb 2011)(Citation: Aleks Weapons Nov 2015)(Citation: Frisk DMA August 2016)(Citation: McMillan Pwn March 2012)

### Detection

Asset management systems may help with the detection of computer systems or network devices that should not exist on a network. 

Endpoint sensors may be able to detect the addition of hardware via USB, Thunderbolt, and other external device communication ports.

### Defenses Bypassed



### Data Sources

  - Application Log: Application Log Content
  -  Drive: Drive Creation
  -  Network Traffic: Network Traffic Flow
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1200
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1200
```
