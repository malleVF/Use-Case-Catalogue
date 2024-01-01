---
created: 2019-08-30
last_modified: 2023-10-16
version: 1.2
tactics: Discovery
url: https://attack.mitre.org/techniques/T1538
platforms: Azure AD, Google Workspace, IaaS, Office 365
tags: [T1538, techniques, Discovery]
---

## Cloud Service Dashboard

### Description

An adversary may use a cloud service dashboard GUI with stolen credentials to gain useful information from an operational cloud environment, such as specific services, resources, and features. For example, the GCP Command Center can be used to view all assets, findings of potential security risks, and to run additional queries, such as finding public IP addresses and open ports.(Citation: Google Command Center Dashboard)

Depending on the configuration of the environment, an adversary may be able to enumerate more information via the graphical dashboard than an API. This allows the adversary to gain information without making any API requests.

### Detection

Monitor account activity logs to see actions performed and activity associated with the cloud service management console. Some cloud providers, such as AWS, provide distinct log events for login attempts to the management console.(Citation: AWS Console Sign-in Events)

### Defenses Bypassed



### Data Sources

  - Logon Session: Logon Session Creation
  -  User Account: User Account Authentication
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1538
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1538
```
