---
created: 2019-09-16
last_modified: 2023-03-30
version: 1.3
tactics: Discovery
url: https://attack.mitre.org/techniques/T1518
platforms: Azure AD, Google Workspace, IaaS, Linux, Office 365, SaaS, Windows, macOS
tags: [T1518, techniques, Discovery]
---

## Software Discovery

### Description

Adversaries may attempt to get a listing of software and software versions that are installed on a system or in a cloud environment. Adversaries may use the information from [Software Discovery](https://attack.mitre.org/techniques/T1518) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

Adversaries may attempt to enumerate software for a variety of reasons, such as figuring out what security measures are present or if the compromised system has a version of software that is vulnerable to [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068).

### Detection

System and network discovery techniques normally occur throughout an operation as an adversary learns the environment. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as lateral movement, based on the information obtained.

Monitor processes and command-line arguments for actions that could be taken to gather system and network information. Remote access tools with built-in features may interact directly with the Windows API to gather information. Information may also be acquired through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).

### Defenses Bypassed



### Data Sources

  - Command: Command Execution
  -  Firewall: Firewall Enumeration
  -  Firewall: Firewall Metadata
  -  Process: OS API Execution
  -  Process: Process Creation
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1518
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "Testing Runbooks" AND #T1518
```
