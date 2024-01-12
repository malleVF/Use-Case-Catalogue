---
created: 2017-05-31
last_modified: 2023-10-01
version: 2.1
tactics: Defense Evasion
url: https://attack.mitre.org/techniques/T1006
platforms: Windows
tags: [T1006, techniques, Defense_Evasion]
---

## Direct Volume Access

### Description

Adversaries may directly access a volume to bypass file access controls and file system monitoring. Windows allows programs to have direct access to logical volumes. Programs with direct access may read and write files directly from the drive by analyzing file system data structures. This technique may bypass Windows file access controls as well as file system monitoring tools. (Citation: Hakobyan 2009)

Utilities, such as `NinjaCopy`, exist to perform these actions in PowerShell.(Citation: Github PowerSploit Ninjacopy) Adversaries may also use built-in or third-party utilities (such as `vssadmin`, `wbadmin`, and [esentutl](https://attack.mitre.org/software/S0404)) to create shadow copies or backups of data from system volumes.(Citation: LOLBAS Esentutl)

### Detection

Monitor handle opens on drive volumes that are made by processes to determine when they may directly access logical drives. (Citation: Github PowerSploit Ninjacopy)

Monitor processes and command-line arguments for actions that could be taken to copy files from the logical drive and evade common file system protections. Since this technique may also be used through [PowerShell](https://attack.mitre.org/techniques/T1059/001), additional logging of PowerShell scripts is recommended.

### Defenses Bypassed

File monitoring, File system access controls

### Data Sources

  - Command: Command Execution
  -  Drive: Drive Access
  -  File: File Creation
### Detection Rule

```query
tag: detection_rule
tag: T1006
```

### Rule Testing

```query
tag: atomic_test
tag: T1006
```
