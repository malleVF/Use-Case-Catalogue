---
created: 2019-11-13
last_modified: 2022-04-19
version: 1.1
tactics: Defense Evasion, Persistence
url: https://attack.mitre.org/techniques/T1542
platforms: Linux, Network, Windows, macOS
tags: [T1542, techniques, Defense_Evasion,Persistence]
---

## Pre-OS Boot

### Description

Adversaries may abuse Pre-OS Boot mechanisms as a way to establish persistence on a system. During the booting process of a computer, firmware and various startup services are loaded before the operating system. These programs control flow of execution before the operating system takes control.(Citation: Wikipedia Booting)

Adversaries may overwrite data in boot drivers or firmware such as BIOS (Basic Input/Output System) and The Unified Extensible Firmware Interface (UEFI) to persist on systems at a layer below the operating system. This can be particularly difficult to detect as malware at this level will not be detected by host software-based defenses.

### Detection

Perform integrity checking on pre-OS boot mechanisms that can be manipulated for malicious purposes. Take snapshots of boot records and firmware and compare against known good images. Log changes to boot records, BIOS, and EFI, which can be performed by API calls, and compare against known good behavior and patching.

Disk check, forensic utilities, and data from device drivers (i.e. processes and API calls) may reveal anomalies that warrant deeper investigation.(Citation: ITWorld Hard Disk Health Dec 2014)

### Defenses Bypassed

Anti-virus, File monitoring, Host intrusion prevention systems

### Data Sources

  - Command: Command Execution
  -  Drive: Drive Modification
  -  Driver: Driver Metadata
  -  Firmware: Firmware Modification
  -  Network Traffic: Network Connection Creation
  -  Process: OS API Execution
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1542
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1542
```
