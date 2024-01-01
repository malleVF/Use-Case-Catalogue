---
created: 2018-04-18
last_modified: 2022-03-08
version: 2.1
tactics: Defense Evasion
url: https://attack.mitre.org/techniques/T1207
platforms: Windows
tags: [T1207, techniques, Defense_Evasion]
---

## Rogue Domain Controller

### Description

Adversaries may register a rogue Domain Controller to enable manipulation of Active Directory data. DCShadow may be used to create a rogue Domain Controller (DC). DCShadow is a method of manipulating Active Directory (AD) data, including objects and schemas, by registering (or reusing an inactive registration) and simulating the behavior of a DC. (Citation: DCShadow Blog) Once registered, a rogue DC may be able to inject and replicate changes into AD infrastructure for any domain object, including credentials and keys.

Registering a rogue DC involves creating a new server and nTDSDSA objects in the Configuration partition of the AD schema, which requires Administrator privileges (either Domain or local to the DC) or the KRBTGT hash. (Citation: Adsecurity Mimikatz Guide)

This technique may bypass system logging and security monitors such as security information and event management (SIEM) products (since actions taken on a rogue DC may not be reported to these sensors). (Citation: DCShadow Blog) The technique may also be used to alter and delete replication and other associated metadata to obstruct forensic analysis. Adversaries may also utilize this technique to perform [SID-History Injection](https://attack.mitre.org/techniques/T1134/005) and/or manipulate AD objects (such as accounts, access control lists, schemas) to establish backdoors for Persistence. (Citation: DCShadow Blog)

### Detection

Monitor and analyze network traffic associated with data replication (such as calls to DrsAddEntry, DrsReplicaAdd, and especially GetNCChanges) between DCs as well as to/from non DC hosts. (Citation: GitHub DCSYNCMonitor) (Citation: DCShadow Blog) DC replication will naturally take place every 15 minutes but can be triggered by an adversary or by legitimate urgent changes (ex: passwords). Also consider monitoring and alerting on the replication of AD objects (Audit Detailed Directory Service Replication Events 4928 and 4929). (Citation: DCShadow Blog)

Leverage AD directory synchronization (DirSync) to monitor changes to directory state using AD replication cookies. (Citation: Microsoft DirSync) (Citation: ADDSecurity DCShadow Feb 2018)

Baseline and periodically analyze the Configuration partition of the AD schema and alert on creation of nTDSDSA objects. (Citation: DCShadow Blog)

Investigate usage of Kerberos Service Principal Names (SPNs), especially those associated with services (beginning with ?GC/?) by computers not present in the DC organizational unit (OU). The SPN associated with the Directory Replication Service (DRS) Remote Protocol interface (GUID E3514235?4B06?11D1-AB04?00C04FC2DCD2) can be set without logging. (Citation: ADDSecurity DCShadow Feb 2018) A rogue DC must authenticate as a service using these two SPNs for the replication process to successfully complete.

### Defenses Bypassed

Log analysis

### Data Sources

  - Active Directory: Active Directory Object Creation
  -  Active Directory: Active Directory Object Modification
  -  Network Traffic: Network Traffic Content
  -  User Account: User Account Authentication
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1207
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1207
```
