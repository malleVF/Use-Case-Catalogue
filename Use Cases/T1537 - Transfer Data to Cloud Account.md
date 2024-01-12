---
created: 2019-08-30
last_modified: 2022-06-16
version: 1.3
tactics: Exfiltration
url: https://attack.mitre.org/techniques/T1537
platforms: IaaS
tags: [T1537, techniques, Exfiltration]
---

## Transfer Data to Cloud Account

### Description

Adversaries may exfiltrate data by transferring the data, including backups of cloud environments, to another cloud account they control on the same service to avoid typical file transfers/downloads and network-based exfiltration detection.

A defender who is monitoring for large transfers to outside the cloud environment through normal file transfers or over command and control channels may not be watching for data transfers to another account within the same cloud provider. Such transfers may utilize existing cloud provider APIs and the internal address space of the cloud provider to blend into normal traffic or avoid data transfers over external network interfaces.

Incidents have been observed where adversaries have created backups of cloud instances and transferred them to separate accounts.(Citation: DOJ GRU Indictment Jul 2018) 

### Detection

Monitor account activity for attempts to share data, snapshots, or backups with untrusted or unusual accounts on the same cloud service provider. Monitor for anomalous file transfer activity between accounts and to untrusted VPCs. 

In AWS, sharing an Elastic Block Store (EBS) snapshot, either with specified users or publicly, generates a ModifySnapshotAttribute event in CloudTrail logs.(Citation: AWS EBS Snapshot Sharing) Similarly, in Azure, creating a Shared Access Signature (SAS) URI for a Virtual Hard Disk (VHS) snapshot generates a "Get Snapshot SAS URL" event in Activity Logs.(Citation: Azure Blob Snapshots)(Citation: Azure Shared Access Signature)

### Defenses Bypassed



### Data Sources

  - Cloud Storage: Cloud Storage Creation
  -  Cloud Storage: Cloud Storage Metadata
  -  Cloud Storage: Cloud Storage Modification
  -  Network Traffic: Network Traffic Content
  -  Snapshot: Snapshot Creation
  -  Snapshot: Snapshot Metadata
  -  Snapshot: Snapshot Modification
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1537
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "Testing Runbooks" AND #T1537
```
