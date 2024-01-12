---
created: 2017-05-31
last_modified: 2023-04-12
version: 1.6
tactics: Collection
url: https://attack.mitre.org/techniques/T1005
platforms: Linux, Network, Windows, macOS
tags: [T1005, techniques, Collection]
---

## Data from Local System

### Description

Adversaries may search local system sources, such as file systems and configuration files or local databases, to find files of interest and sensitive data prior to Exfiltration.

Adversaries may do this using a [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059), such as [cmd](https://attack.mitre.org/software/S0106) as well as a [Network Device CLI](https://attack.mitre.org/techniques/T1059/008), which have functionality to interact with the file system to gather information.(Citation: show_run_config_cmd_cisco) Adversaries may also use [Automated Collection](https://attack.mitre.org/techniques/T1119) on the local system.


### Detection

Monitor processes and command-line arguments for actions that could be taken to collect files from a system. Remote access tools with built-in features may interact directly with the Windows API to gather data. Further, [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) commands may also be used to collect files such as configuration files with built-in features native to the network device platform.(Citation: Mandiant APT41 Global Intrusion )(Citation: US-CERT-TA18-106A) Monitor CLI activity for unexpected or unauthorized use commands being run by non-standard users from non-standard locations. Data may also be acquired through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).

For network infrastructure devices, collect AAA logging to monitor `show` commands that view configuration files. 

### Defenses Bypassed



### Data Sources

  - Command: Command Execution
  -  File: File Access
  -  Process: OS API Execution
  -  Process: Process Creation
  -  Script: Script Execution
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1005
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "Testing Runbooks" AND #T1005
```
