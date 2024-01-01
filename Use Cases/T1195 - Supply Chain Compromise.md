---
created: 2018-04-18
last_modified: 2023-03-30
version: 1.5
tactics: Initial Access
url: https://attack.mitre.org/techniques/T1195
platforms: Linux, Windows, macOS
tags: [T1195, techniques, Initial_Access]
---

## Supply Chain Compromise

### Description

Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer for the purpose of data or system compromise.

Supply chain compromise can take place at any stage of the supply chain including:

* Manipulation of development tools
* Manipulation of a development environment
* Manipulation of source code repositories (public or private)
* Manipulation of source code in open-source dependencies
* Manipulation of software update/distribution mechanisms
* Compromised/infected system images (multiple cases of removable media infected at the factory)(Citation: IBM Storwize)(Citation: Schneider Electric USB Malware) 
* Replacement of legitimate software with modified versions
* Sales of modified/counterfeit products to legitimate distributors
* Shipment interdiction

While supply chain compromise can impact any component of hardware or software, adversaries looking to gain execution have often focused on malicious additions to legitimate software in software distribution or update channels.(Citation: Avast CCleaner3 2018)(Citation: Microsoft Dofoil 2018)(Citation: Command Five SK 2011) Targeting may be specific to a desired victim set or malicious software may be distributed to a broad set of consumers but only move on to additional tactics on specific victims.(Citation: Symantec Elderwood Sept 2012)(Citation: Avast CCleaner3 2018)(Citation: Command Five SK 2011) Popular open source projects that are used as dependencies in many applications may also be targeted as a means to add malicious code to users of the dependency.(Citation: Trendmicro NPM Compromise)

### Detection

Use verification of distributed binaries through hash checking or other integrity checking mechanisms. Scan downloads for malicious signatures and attempt to test software and updates prior to deployment while taking note of potential suspicious activity. Perform physical inspection of hardware to look for potential tampering.

### Defenses Bypassed



### Data Sources

  - File: File Metadata
  -  Sensor Health: Host Status
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1195
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1195
```
