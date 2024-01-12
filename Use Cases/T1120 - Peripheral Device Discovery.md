---
created: 2017-05-31
last_modified: 2023-03-30
version: 1.3
tactics: Discovery
url: https://attack.mitre.org/techniques/T1120
platforms: Linux, Windows, macOS
tags: [T1120, techniques, Discovery]
---

## Peripheral Device Discovery

### Description

Adversaries may attempt to gather information about attached peripheral devices and components connected to a computer system.(Citation: Peripheral Discovery Linux)(Citation: Peripheral Discovery macOS) Peripheral devices could include auxiliary resources that support a variety of functionalities such as keyboards, printers, cameras, smart card readers, or removable storage. The information may be used to enhance their awareness of the system and network environment or may be used for further actions.

### Detection

System and network discovery techniques normally occur throughout an operation as an adversary learns the environment. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities based on the information obtained.

Monitor processes and command-line arguments for actions that could be taken to gather system and network information. Remote access tools with built-in features may interact directly with the Windows API to gather information. Information may also be acquired through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).

### Defenses Bypassed



### Data Sources

  - Command: Command Execution
  -  Process: OS API Execution
  -  Process: Process Creation
### Detection Rule

```query
tag: detection_rule
tag: T1120
```

### Rule Testing

```query
tag: atomic_test
tag: T1120
```
