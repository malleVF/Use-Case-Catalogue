---
created: 2019-08-30
last_modified: 2023-09-05
version: 1.2
tactics: Defense Evasion
url: https://attack.mitre.org/techniques/T1578
platforms: IaaS
tags: [T1578, techniques, Defense_Evasion]
---

## Modify Cloud Compute Infrastructure

### Description

An adversary may attempt to modify a cloud account's compute service infrastructure to evade defenses. A modification to the compute service infrastructure can include the creation, deletion, or modification of one or more components such as compute instances, virtual machines, and snapshots.

Permissions gained from the modification of infrastructure components may bypass restrictions that prevent access to existing infrastructure. Modifying infrastructure components may also allow an adversary to evade detection and remove evidence of their presence.(Citation: Mandiant M-Trends 2020)

### Detection

Establish centralized logging for the activity of cloud compute infrastructure components. Monitor for suspicious sequences of events, such as the creation of multiple snapshots within a short period of time or the mount of a snapshot to a new instance by a new or unexpected user. To reduce false positives, valid change management procedures could introduce a known identifier that is logged with the change (e.g., tag or header) if supported by the cloud provider, to help distinguish valid, expected actions from malicious ones.

### Defenses Bypassed



### Data Sources

  - Cloud Service: Cloud Service Metadata
  -  Instance: Instance Creation
  -  Instance: Instance Deletion
  -  Instance: Instance Metadata
  -  Instance: Instance Modification
  -  Instance: Instance Start
  -  Instance: Instance Stop
  -  Snapshot: Snapshot Creation
  -  Snapshot: Snapshot Deletion
  -  Snapshot: Snapshot Metadata
  -  Snapshot: Snapshot Modification
  -  Volume: Volume Creation
  -  Volume: Volume Deletion
  -  Volume: Volume Metadata
  -  Volume: Volume Modification
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1578
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1578
```
