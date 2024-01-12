---
created: 2017-05-31
last_modified: 2023-03-30
version: 1.5
tactics: Discovery
url: https://attack.mitre.org/techniques/T1083
platforms: Linux, Network, Windows, macOS
tags: [T1083, techniques, Discovery]
---

## File and Directory Discovery

### Description

Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system. Adversaries may use the information from [File and Directory Discovery](https://attack.mitre.org/techniques/T1083) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

Many command shell utilities can be used to obtain this information. Examples include <code>dir</code>, <code>tree</code>, <code>ls</code>, <code>find</code>, and <code>locate</code>.(Citation: Windows Commands JPCERT) Custom tools may also be used to gather file and directory information and interact with the [Native API](https://attack.mitre.org/techniques/T1106). Adversaries may also leverage a [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) on network devices to gather file and directory information (e.g. <code>dir</code>, <code>show flash</code>, and/or <code>nvram</code>).(Citation: US-CERT-TA18-106A)

### Detection

System and network discovery techniques normally occur throughout an operation as an adversary learns the environment. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as Collection and Exfiltration, based on the information obtained.

Monitor processes and command-line arguments for actions that could be taken to gather system and network information. Remote access tools with built-in features may interact directly with the Windows API to gather information. Information may also be acquired through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001). Further, [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) commands may also be used to gather file and directory information with built-in features native to the network device platform.  Monitor CLI activity for unexpected or unauthorized use of commands being run by non-standard users from non-standard locations.  

### Defenses Bypassed



### Data Sources

  - Command: Command Execution
  -  Process: OS API Execution
  -  Process: Process Creation
### Detection Rule

```query
tag: detection_rule
tag: T1083
```

### Rule Testing

```query
tag: atomic_test
tag: T1083
```
