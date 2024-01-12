---
created: 2017-05-31
last_modified: 2023-08-11
version: 2.2
tactics: Persistence, Privilege Escalation
url: https://attack.mitre.org/techniques/T1037
platforms: Linux, Windows, macOS
tags: [T1037, techniques, Persistence,_Privilege_Escalation]
---

## Boot or Logon Initialization Scripts

### Description

Adversaries may use scripts automatically executed at boot or logon initialization to establish persistence. Initialization scripts can be used to perform administrative functions, which may often execute other programs or send information to an internal logging server. These scripts can vary based on operating system and whether applied locally or remotely.  

Adversaries may use these scripts to maintain persistence on a single system. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary. 

An adversary may also be able to escalate their privileges since some boot or logon initialization scripts run with higher privileges.

### Detection

Monitor logon scripts for unusual access by abnormal users or at abnormal times. Look for files added or modified by unusual accounts outside of normal administration duties. Monitor running process for actions that could be indicative of abnormal programs or executables running upon logon.

### Defenses Bypassed



### Data Sources

  - Active Directory: Active Directory Object Modification
  -  Command: Command Execution
  -  File: File Creation
  -  File: File Modification
  -  Process: Process Creation
  -  Windows Registry: Windows Registry Key Creation
### Detection Rule

```query
tag: detection_rule
tag: T1037
```

### Rule Testing

```query
tag: atomic_test
tag: T1037
```
