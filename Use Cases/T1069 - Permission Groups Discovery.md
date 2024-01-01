---
created: 2017-05-31
last_modified: 2023-04-15
version: 2.5
tactics: Discovery
url: https://attack.mitre.org/techniques/T1069
platforms: Azure AD, Containers, Google Workspace, IaaS, Linux, Office 365, SaaS, Windows, macOS
tags: [T1069, techniques, Discovery]
---

## Permission Groups Discovery

### Description

Adversaries may attempt to discover group and permission settings. This information can help adversaries determine which user accounts and groups are available, the membership of users in particular groups, and which users and groups have elevated permissions.

Adversaries may attempt to discover group permission settings in many different ways. This data may provide the adversary with information about the compromised environment that can be used in follow-on activity and targeting.(Citation: CrowdStrike BloodHound April 2018)

### Detection

System and network discovery techniques normally occur throughout an operation as an adversary learns the environment. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as Lateral Movement, based on the information obtained.

Monitor processes and command-line arguments for actions that could be taken to gather system and network information. Remote access tools with built-in features may interact directly with the Windows API to gather information. Information may also be acquired through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001). Monitor container logs for commands and/or API calls related to listing permissions for pods and nodes, such as <code>kubectl auth can-i</code>.(Citation: K8s Authorization Overview)

### Defenses Bypassed



### Data Sources

  - Application Log: Application Log Content
  -  Command: Command Execution
  -  Group: Group Enumeration
  -  Group: Group Metadata
  -  Process: Process Creation
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1069
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1069
```
