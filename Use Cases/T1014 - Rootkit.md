---
created: 2017-05-31
last_modified: 2023-03-30
version: 1.1
tactics: Defense Evasion
url: https://attack.mitre.org/techniques/T1014
platforms: Linux, Windows, macOS
tags: [T1014, techniques, Defense_Evasion]
---

## Rootkit

### Description

Adversaries may use rootkits to hide the presence of programs, files, network connections, services, drivers, and other system components. Rootkits are programs that hide the existence of malware by intercepting/hooking and modifying operating system API calls that supply system information. (Citation: Symantec Windows Rootkits) 

Rootkits or rootkit enabling functionality may reside at the user or kernel level in the operating system or lower, to include a hypervisor, Master Boot Record, or [System Firmware](https://attack.mitre.org/techniques/T1542/001). (Citation: Wikipedia Rootkit) Rootkits have been seen for Windows, Linux, and Mac OS X systems. (Citation: CrowdStrike Linux Rootkit) (Citation: BlackHat Mac OSX Rootkit)

### Detection

Some rootkit protections may be built into anti-virus or operating system software. There are dedicated rootkit detection tools that look for specific types of rootkit behavior. Monitor for the existence of unrecognized DLLs, devices, services, and changes to the MBR. (Citation: Wikipedia Rootkit)

### Defenses Bypassed

Anti-virus, Application Control, File Monitoring, Host Intrusion Prevention Systems, Signature-based Detection, System Access Controls

### Data Sources

  - Drive: Drive Modification
  -  File: File Modification
  -  Firmware: Firmware Modification
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1014
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1014
```
