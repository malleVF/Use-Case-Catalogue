---
created: 2020-03-09
last_modified: 2023-09-05
version: 1.3
tactics: Exfiltration
url: https://attack.mitre.org/techniques/T1567
platforms: Google Workspace, Linux, Office 365, SaaS, Windows, macOS
tags: [T1567, techniques, Exfiltration]
---

## Exfiltration Over Web Service

### Description

Adversaries may use an existing, legitimate external Web service to exfiltrate data rather than their primary command and control channel. Popular Web services acting as an exfiltration mechanism may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to compromise. Firewall rules may also already exist to permit traffic to these services.

Web service providers also commonly use SSL/TLS encryption, giving adversaries an added level of protection.

### Detection

Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. User behavior monitoring may help to detect abnormal patterns of activity.

### Defenses Bypassed



### Data Sources

  - Application Log: Application Log Content
  -  Command: Command Execution
  -  File: File Access
  -  Network Traffic: Network Connection Creation
  -  Network Traffic: Network Traffic Content
  -  Network Traffic: Network Traffic Flow
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1567
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1567
```
