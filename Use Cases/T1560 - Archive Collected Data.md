---
created: 2020-02-20
last_modified: 2022-01-04
version: 1.0
tactics: Collection
url: https://attack.mitre.org/techniques/T1560
platforms: Linux, Windows, macOS
tags: [T1560, techniques, Collection]
---

## Archive Collected Data

### Description

An adversary may compress and/or encrypt data that is collected prior to exfiltration. Compressing the data can help to obfuscate the collected data and minimize the amount of data sent over the network. Encryption can be used to hide information that is being exfiltrated from detection or make exfiltration less conspicuous upon inspection by a defender.

Both compression and encryption are done prior to exfiltration, and can be performed using a utility, 3rd party library, or custom method.

### Detection

Archival software and archived files can be detected in many ways. Common utilities that may be present on the system or brought in by an adversary may be detectable through process monitoring and monitoring for command-line arguments for known archival utilities. This may yield a significant number of benign events, depending on how systems in the environment are typically used.

A process that loads the Windows DLL crypt32.dll may be used to perform encryption, decryption, or verification of file signatures.

Consider detecting writing of files with extensions and/or headers associated with compressed or encrypted file types. Detection efforts may focus on follow-on exfiltration activity, where compressed or encrypted files can be detected in transit with a network intrusion detection or data loss prevention system analyzing file headers.(Citation: Wikipedia File Header Signatures)

### Defenses Bypassed



### Data Sources

  - Command: Command Execution
  -  File: File Creation
  -  Process: Process Creation
  -  Script: Script Execution
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1560
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1560
```
