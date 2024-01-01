---
created: 2021-04-01
last_modified: 2021-10-15
version: 1.0
tactics: Discovery
url: https://attack.mitre.org/techniques/T1614
platforms: IaaS, Linux, Windows, macOS
tags: [T1614, techniques, Discovery]
---

## System Location Discovery

### Description


Adversaries may gather information in an attempt to calculate the geographical location of a victim host. Adversaries may use the information from [System Location Discovery](https://attack.mitre.org/techniques/T1614) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

Adversaries may attempt to infer the location of a system using various system checks, such as time zone, keyboard layout, and/or language settings.(Citation: FBI Ragnar Locker 2020)(Citation: Sophos Geolocation 2016)(Citation: Bleepingcomputer RAT malware 2020) Windows API functions such as <code>GetLocaleInfoW</code> can also be used to determine the locale of the host.(Citation: FBI Ragnar Locker 2020) In cloud environments, an instance's availability zone may also be discovered by accessing the instance metadata service from the instance.(Citation: AWS Instance Identity Documents)(Citation: Microsoft Azure Instance Metadata 2021)

Adversaries may also attempt to infer the location of a victim host using IP addressing, such as via online geolocation IP-lookup services.(Citation: Securelist Trasparent Tribe 2020)(Citation: Sophos Geolocation 2016)

### Detection

System and network discovery techniques normally occur throughout an operation as an adversary learns the environment. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities based on the information obtained.

Monitor processes and command-line arguments for actions that could be taken to gather system location information. Remote access tools with built-in features may interact directly with the Windows API, such as calling <code> GetLocaleInfoW</code> to gather information.(Citation: FBI Ragnar Locker 2020)

Monitor traffic flows to geo-location service provider sites, such as ip-api and ipinfo.

### Defenses Bypassed



### Data Sources

  - Command: Command Execution
  -  Process: OS API Execution
  -  Process: Process Creation
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1614
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1614
```
