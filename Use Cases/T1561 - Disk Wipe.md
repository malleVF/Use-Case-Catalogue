---
created: 2020-02-20
last_modified: 2023-04-20
version: 1.1
tactics: Impact
url: https://attack.mitre.org/techniques/T1561
platforms: Linux, Network, Windows, macOS
tags: [T1561, techniques, Impact]
---

## Disk Wipe

### Description

Adversaries may wipe or corrupt raw disk data on specific systems or in large numbers in a network to interrupt availability to system and network resources. With direct write access to a disk, adversaries may attempt to overwrite portions of disk data. Adversaries may opt to wipe arbitrary portions of disk data and/or wipe disk structures like the master boot record (MBR). A complete wipe of all disk sectors may be attempted.

To maximize impact on the target organization in operations where network-wide availability interruption is the goal, malware used for wiping disks may have worm-like features to propagate across a network by leveraging additional techniques like [Valid Accounts](https://attack.mitre.org/techniques/T1078), [OS Credential Dumping](https://attack.mitre.org/techniques/T1003), and [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002).(Citation: Novetta Blockbuster Destructive Malware)

On network devices, adversaries may wipe configuration files and other data from the device using [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) commands such as `erase`.(Citation: erase_cmd_cisco)

### Detection

Look for attempts to read/write to sensitive locations like the partition boot sector, master boot record, disk partition table, or BIOS parameter block/superblock. Monitor for direct access read/write attempts using the <code>\\\\.\\</code> notation.(Citation: Microsoft Sysmon v6 May 2017) Monitor for unusual kernel driver installation activity.

### Defenses Bypassed



### Data Sources

  - Command: Command Execution
  -  Drive: Drive Access
  -  Drive: Drive Modification
  -  Driver: Driver Load
  -  Process: Process Creation
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1561
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "Testing Runbooks" AND #T1561
```
