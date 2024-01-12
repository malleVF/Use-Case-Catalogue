---
created: 2020-02-21
last_modified: 2023-10-20
version: 1.5
tactics: Defense Evasion
url: https://attack.mitre.org/techniques/T1562
platforms: Containers, IaaS, Linux, Network, Office 365, Windows, macOS
tags: [T1562, techniques, Defense_Evasion]
---

## Impair Defenses

### Description

Adversaries may maliciously modify components of a victim environment in order to hinder or disable defensive mechanisms. This not only involves impairing preventative defenses, such as firewalls and anti-virus, but also detection capabilities that defenders can use to audit activity and identify malicious behavior. This may also span both native defenses as well as supplemental capabilities installed by users and administrators.

Adversaries may also impair routine operations that contribute to defensive hygiene, such as blocking users from logging out of a computer or stopping it from being shut down. These restrictions can further enable malicious operations as well as the continued propagation of incidents.(Citation: Emotet shutdown)

Adversaries could also target event aggregation and analysis mechanisms, or otherwise disrupt these procedures by altering other system components.

### Detection

Monitor processes and command-line arguments to see if security tools or logging services are killed or stop running. Monitor Registry edits for modifications to services and startup programs that correspond to security tools.  Lack of log events may be suspicious.

Monitor environment variables and APIs that can be leveraged to disable security measures.

### Defenses Bypassed

Anti-virus, Digital Certificate Validation, File monitoring, Firewall, Host forensic analysis, Host intrusion prevention systems, Log analysis, Signature-based detection

### Data Sources

  - Cloud Service: Cloud Service Disable
  -  Cloud Service: Cloud Service Modification
  -  Command: Command Execution
  -  Driver: Driver Load
  -  File: File Deletion
  -  File: File Modification
  -  Firewall: Firewall Disable
  -  Firewall: Firewall Rule Modification
  -  Process: OS API Execution
  -  Process: Process Creation
  -  Process: Process Modification
  -  Process: Process Termination
  -  Script: Script Execution
  -  Sensor Health: Host Status
  -  Service: Service Metadata
  -  User Account: User Account Modification
  -  Windows Registry: Windows Registry Key Deletion
  -  Windows Registry: Windows Registry Key Modification
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1562
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "Testing Runbooks" AND #T1562
```
