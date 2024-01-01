---
created: 2019-03-14
last_modified: 2023-10-03
version: 1.2
tactics: Impact
url: https://attack.mitre.org/techniques/T1485
platforms: Containers, IaaS, Linux, Windows, macOS
tags: [T1485, techniques, Impact]
---

## Data Destruction

### Description

Adversaries may destroy data and files on specific systems or in large numbers on a network to interrupt availability to systems, services, and network resources. Data destruction is likely to render stored data irrecoverable by forensic techniques through overwriting files or data on local and remote drives.(Citation: Symantec Shamoon 2012)(Citation: FireEye Shamoon Nov 2016)(Citation: Palo Alto Shamoon Nov 2016)(Citation: Kaspersky StoneDrill 2017)(Citation: Unit 42 Shamoon3 2018)(Citation: Talos Olympic Destroyer 2018) Common operating system file deletion commands such as <code>del</code> and <code>rm</code> often only remove pointers to files without wiping the contents of the files themselves, making the files recoverable by proper forensic methodology. This behavior is distinct from [Disk Content Wipe](https://attack.mitre.org/techniques/T1561/001) and [Disk Structure Wipe](https://attack.mitre.org/techniques/T1561/002) because individual files are destroyed rather than sections of a storage disk or the disk's logical structure.

Adversaries may attempt to overwrite files and directories with randomly generated data to make it irrecoverable.(Citation: Kaspersky StoneDrill 2017)(Citation: Unit 42 Shamoon3 2018) In some cases politically oriented image files have been used to overwrite data.(Citation: FireEye Shamoon Nov 2016)(Citation: Palo Alto Shamoon Nov 2016)(Citation: Kaspersky StoneDrill 2017)

To maximize impact on the target organization in operations where network-wide availability interruption is the goal, malware designed for destroying data may have worm-like features to propagate across a network by leveraging additional techniques like [Valid Accounts](https://attack.mitre.org/techniques/T1078), [OS Credential Dumping](https://attack.mitre.org/techniques/T1003), and [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002).(Citation: Symantec Shamoon 2012)(Citation: FireEye Shamoon Nov 2016)(Citation: Palo Alto Shamoon Nov 2016)(Citation: Kaspersky StoneDrill 2017)(Citation: Talos Olympic Destroyer 2018).

In cloud environments, adversaries may leverage access to delete cloud storage, cloud storage accounts, machine images, and other infrastructure crucial to operations to damage an organization or their customers.(Citation: Data Destruction - Threat Post)(Citation: DOJ  - Cisco Insider)

### Detection

Use process monitoring to monitor the execution and command-line parameters of binaries that could be involved in data destruction activity, such as [SDelete](https://attack.mitre.org/software/S0195). Monitor for the creation of suspicious files as well as high unusual file modification activity. In particular, look for large quantities of file modifications in user directories and under <code>C:\Windows\System32\</code>.

In cloud environments, the occurrence of anomalous high-volume deletion events, such as the <code>DeleteDBCluster</code> and <code>DeleteGlobalCluster</code> events in AWS, or a high quantity of data deletion events, such as <code>DeleteBucket</code>, within a short period of time may indicate suspicious activity.

### Defenses Bypassed



### Data Sources

  - Cloud Storage: Cloud Storage Deletion
  -  Command: Command Execution
  -  File: File Deletion
  -  File: File Modification
  -  Image: Image Deletion
  -  Instance: Instance Deletion
  -  Process: Process Creation
  -  Snapshot: Snapshot Deletion
  -  Volume: Volume Deletion
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1485
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1485
```
