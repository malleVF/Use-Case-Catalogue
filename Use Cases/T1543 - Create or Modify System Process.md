---
created: 2020-01-10
last_modified: 2022-04-20
version: 1.1
tactics: Persistence, Privilege Escalation
url: https://attack.mitre.org/techniques/T1543
platforms: Linux, Windows, macOS
tags: [T1543, techniques, Persistence,_Privilege_Escalation]
---

## Create or Modify System Process

### Description

Adversaries may create or modify system-level processes to repeatedly execute malicious payloads as part of persistence. When operating systems boot up, they can start processes that perform background system functions. On Windows and Linux, these system processes are referred to as services.(Citation: TechNet Services) On macOS, launchd processes known as [Launch Daemon](https://attack.mitre.org/techniques/T1543/004) and [Launch Agent](https://attack.mitre.org/techniques/T1543/001) are run to finish system initialization and load user specific parameters.(Citation: AppleDocs Launch Agent Daemons) 

Adversaries may install new services, daemons, or agents that can be configured to execute at startup or a repeatable interval in order to establish persistence. Similarly, adversaries may modify existing services, daemons, or agents to achieve the same effect.  

Services, daemons, or agents may be created with administrator privileges but executed under root/SYSTEM privileges. Adversaries may leverage this functionality to create or modify system processes in order to escalate privileges.(Citation: OSX Malware Detection)  

### Detection

Monitor for changes to system processes that do not correlate with known software, patch cycles, etc., including by comparing results against a trusted system baseline. New, benign system processes may be created during installation of new software. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as network connections made for Command and Control, learning details about the environment through Discovery, and Lateral Movement.  

Command-line invocation of tools capable of modifying services may be unusual, depending on how systems are typically used in a particular environment. Look for abnormal process call trees from known services and for execution of other commands that could relate to Discovery or other adversary techniques. 

Monitor for changes to files associated with system-level processes.

### Defenses Bypassed



### Data Sources

  - Command: Command Execution
  -  Driver: Driver Load
  -  File: File Creation
  -  File: File Modification
  -  Process: OS API Execution
  -  Process: Process Creation
  -  Service: Service Creation
  -  Service: Service Modification
  -  Windows Registry: Windows Registry Key Creation
  -  Windows Registry: Windows Registry Key Modification
### Detection Rule

```query
tag: detection_rule
tag: T1543
```

### Rule Testing

```query
tag: atomic_test
tag: T1543
```
