---
created: 2023-07-10
last_modified: 2023-09-30
version: 1.0
tactics: Discovery
url: https://attack.mitre.org/techniques/T1654
platforms: IaaS, Linux, Windows, macOS
tags: [T1654, techniques, Discovery]
---

## Log Enumeration

### Description

Adversaries may enumerate system and service logs to find useful data. These logs may highlight various types of valuable insights for an adversary, such as user authentication records ([Account Discovery](https://attack.mitre.org/techniques/T1087)), security or vulnerable software ([Software Discovery](https://attack.mitre.org/techniques/T1518)), or hosts within a compromised network ([Remote System Discovery](https://attack.mitre.org/techniques/T1018)).

Host binaries may be leveraged to collect system logs. Examples include using `wevtutil.exe` or [PowerShell](https://attack.mitre.org/techniques/T1059/001) on Windows to access and/or export security event information.(Citation: WithSecure Lazarus-NoPineapple Threat Intel Report 2023)(Citation: Cadet Blizzard emerges as novel threat actor) In cloud environments, adversaries may leverage utilities such as the Azure VM Agent?s `CollectGuestLogs.exe` to collect security logs from cloud hosted infrastructure.(Citation: SIM Swapping and Abuse of the Microsoft Azure Serial Console)

Adversaries may also target centralized logging infrastructure such as SIEMs. Logs may also be bulk exported and sent to adversary-controlled infrastructure for offline analysis.

### Detection



### Defenses Bypassed



### Data Sources

  - Command: Command Execution
  -  File: File Access
  -  Process: Process Creation
### Detection Rule

```query
tag: detection_rule
tag: T1654
```

### Rule Testing

```query
tag: atomic_test
tag: T1654
```
