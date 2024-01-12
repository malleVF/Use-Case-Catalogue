---
created: 2020-01-22
last_modified: 2022-10-19
version: 1.2
tactics: Persistence, Privilege Escalation
url: https://attack.mitre.org/techniques/T1546
platforms: IaaS, Linux, Office 365, SaaS, Windows, macOS
tags: [T1546, techniques, Persistence,_Privilege_Escalation]
---

## Event Triggered Execution

### Description

Adversaries may establish persistence and/or elevate privileges using system mechanisms that trigger execution based on specific events. Various operating systems have means to monitor and subscribe to events such as logons or other user activity such as running specific applications/binaries. Cloud environments may also support various functions and services that monitor and can be invoked in response to specific cloud events.(Citation: Backdooring an AWS account)(Citation: Varonis Power Automate Data Exfiltration)(Citation: Microsoft DART Case Report 001)

Adversaries may abuse these mechanisms as a means of maintaining persistent access to a victim via repeatedly executing malicious code. After gaining access to a victim system, adversaries may create/modify event triggers to point to malicious content that will be executed whenever the event trigger is invoked.(Citation: FireEye WMI 2015)(Citation: Malware Persistence on OS X)(Citation: amnesia malware)

Since the execution can be proxied by an account with higher permissions, such as SYSTEM or service accounts, an adversary may be able to abuse these triggered execution mechanisms to escalate their privileges. 

### Detection

Monitoring for additions or modifications of mechanisms that could be used to trigger event-based execution, especially the addition of abnormal commands such as execution of unknown programs, opening network sockets, or reaching out across the network. Also look for changes that do not line up with updates, patches, or other planned administrative activity. 

These mechanisms may vary by OS, but are typically stored in central repositories that store configuration information such as the Windows Registry, Common Information Model (CIM), and/or specific named files, the last of which can be hashed and compared to known good values. 

Monitor for processes, API/System calls, and other common ways of manipulating these event repositories. 

Tools such as Sysinternals Autoruns can be used to detect changes to execution triggers that could be attempts at persistence. Also look for abnormal process call trees for execution of other commands that could relate to Discovery actions or other techniques.  

Monitor DLL loads by processes, specifically looking for DLLs that are not recognized or not normally loaded into a process. Look for abnormal process behavior that may be due to a process loading a malicious DLL. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as making network connections for Command and Control, learning details about the environment through Discovery, and conducting Lateral Movement. 

### Defenses Bypassed



### Data Sources

  - Cloud Service: Cloud Service Modification
  -  Command: Command Execution
  -  File: File Creation
  -  File: File Metadata
  -  File: File Modification
  -  Module: Module Load
  -  Process: Process Creation
  -  WMI: WMI Creation
  -  Windows Registry: Windows Registry Key Modification
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1546
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "Testing Runbooks" AND #T1546
```
