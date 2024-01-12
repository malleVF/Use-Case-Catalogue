---
created: 2017-05-31
last_modified: 2022-05-05
version: 1.2
tactics: Defense Evasion
url: https://attack.mitre.org/techniques/T1127
platforms: Windows
tags: [T1127, techniques, Defense_Evasion]
---

## Trusted Developer Utilities Proxy Execution

### Description

Adversaries may take advantage of trusted developer utilities to proxy execution of malicious payloads. There are many utilities used for software development related tasks that can be used to execute code in various forms to assist in development, debugging, and reverse engineering.(Citation: engima0x3 DNX Bypass)(Citation: engima0x3 RCSI Bypass)(Citation: Exploit Monday WinDbg)(Citation: LOLBAS Tracker) These utilities may often be signed with legitimate certificates that allow them to execute on a system and proxy execution of malicious code through a trusted process that effectively bypasses application control solutions.

### Detection

Monitor for abnormal presence of these or other utilities that enable proxy execution that are typically used for development, debugging, and reverse engineering on a system that is not used for these purposes may be suspicious.

Use process monitoring to monitor the execution and arguments of from developer utilities that may be abused. Compare recent invocations of those binaries with prior history of known good arguments and executed binaries to determine anomalous and potentially adversarial activity. It is likely that these utilities will be used by software developers or for other software development related tasks, so if it exists and is used outside of that context, then the event may be suspicious. Command arguments used before and after invocation of the utilities may also be useful in determining the origin and purpose of the binary being executed.

### Defenses Bypassed

Application Control

### Data Sources

  - Command: Command Execution
  -  Process: Process Creation
### Detection Rule

```query
tag: detection_rule
tag: T1127
```

### Rule Testing

```query
tag: atomic_test
tag: T1127
```
