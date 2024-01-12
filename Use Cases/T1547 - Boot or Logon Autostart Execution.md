---
created: 2020-01-23
last_modified: 2023-03-30
version: 1.1
tactics: Persistence, Privilege Escalation
url: https://attack.mitre.org/techniques/T1547
platforms: Linux, Windows, macOS
tags: [T1547, techniques, Persistence,_Privilege_Escalation]
---

## Boot or Logon Autostart Execution

### Description

Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence or gain higher-level privileges on compromised systems. Operating systems may have mechanisms for automatically running a program on system boot or account logon.(Citation: Microsoft Run Key)(Citation: MSDN Authentication Packages)(Citation: Microsoft TimeProvider)(Citation: Cylance Reg Persistence Sept 2013)(Citation: Linux Kernel Programming) These mechanisms may include automatically executing programs that are placed in specially designated directories or are referenced by repositories that store configuration information, such as the Windows Registry. An adversary may achieve the same goal by modifying or extending features of the kernel.

Since some boot or logon autostart programs run with higher privileges, an adversary may leverage these to elevate privileges.

### Detection

Monitor for additions or modifications of mechanisms that could be used to trigger autostart execution, such as relevant additions to the Registry. Look for changes that are not correlated with known updates, patches, or other planned administrative activity. Tools such as Sysinternals Autoruns may also be used to detect system autostart configuration changes that could be attempts at persistence.(Citation: TechNet Autoruns)  Changes to some autostart configuration settings may happen under normal conditions when legitimate software is installed. 

Suspicious program execution as autostart programs may show up as outlier processes that have not been seen before when compared against historical data.To increase confidence of malicious activity, data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as network connections made for Command and Control, learning details about the environment through Discovery, and Lateral Movement.

Monitor DLL loads by processes, specifically looking for DLLs that are not recognized or not normally loaded into a process. Look for abnormal process behavior that may be due to a process loading a malicious DLL.

Monitor for abnormal usage of utilities and command-line parameters involved in kernel modification or driver installation.

### Defenses Bypassed



### Data Sources

  - Command: Command Execution
  -  Driver: Driver Load
  -  File: File Creation
  -  File: File Modification
  -  Kernel: Kernel Module Load
  -  Module: Module Load
  -  Process: OS API Execution
  -  Process: Process Creation
  -  Windows Registry: Windows Registry Key Creation
  -  Windows Registry: Windows Registry Key Modification
### Detection Rule

```query
tag: detection_rule
tag: T1547
```

### Rule Testing

```query
tag: atomic_test
tag: T1547
```
