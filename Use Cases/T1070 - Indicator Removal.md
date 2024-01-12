---
created: 2017-05-31
last_modified: 2023-04-11
version: 2.1
tactics: Defense Evasion
url: https://attack.mitre.org/techniques/T1070
platforms: Containers, Google Workspace, Linux, Network, Office 365, Windows, macOS
tags: [T1070, techniques, Defense_Evasion]
---

## Indicator Removal

### Description

Adversaries may delete or modify artifacts generated within systems to remove evidence of their presence or hinder defenses. Various artifacts may be created by an adversary or something that can be attributed to an adversary?s actions. Typically these artifacts are used as defensive indicators related to monitored events, such as strings from downloaded files, logs that are generated from user actions, and other data analyzed by defenders. Location, format, and type of artifact (such as command or login history) are often specific to each platform.

Removal of these indicators may interfere with event collection, reporting, or other processes used to detect intrusion activity. This may compromise the integrity of security solutions by causing notable events to go unreported. This activity may also impede forensic analysis and incident response, due to lack of sufficient data to determine what occurred.

### Detection

File system monitoring may be used to detect improper deletion or modification of indicator files.  Events not stored on the file system may require different detection mechanisms.

### Defenses Bypassed

Anti-virus, Host intrusion prevention systems, Log analysis

### Data Sources

  - Application Log: Application Log Content
  -  Command: Command Execution
  -  File: File Deletion
  -  File: File Metadata
  -  File: File Modification
  -  Firewall: Firewall Rule Modification
  -  Network Traffic: Network Traffic Content
  -  Process: OS API Execution
  -  Process: Process Creation
  -  Scheduled Job: Scheduled Job Modification
  -  User Account: User Account Authentication
  -  User Account: User Account Deletion
  -  Windows Registry: Windows Registry Key Deletion
  -  Windows Registry: Windows Registry Key Modification
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1070
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "Testing Runbooks" AND #T1070
```
