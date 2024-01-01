---
created: 2019-04-17
last_modified: 2021-10-18
version: 1.3
tactics: Defense Evasion, Discovery
url: https://attack.mitre.org/techniques/T1497
platforms: Linux, Windows, macOS
tags: [T1497, techniques, Defense_Evasion,Discovery]
---

## Virtualization_Sandbox Evasion

### Description

Adversaries may employ various means to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads. Adversaries may use the information learned from [Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497) during automated discovery to shape follow-on behaviors.(Citation: Deloitte Environment Awareness)

Adversaries may use several methods to accomplish [Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497) such as checking for security monitoring tools (e.g., Sysinternals, Wireshark, etc.) or other system artifacts associated with analysis or virtualization. Adversaries may also check for legitimate user activity to help determine if it is in an analysis environment. Additional methods include use of sleep timers or loops within malware code to avoid operating within a temporary sandbox.(Citation: Unit 42 Pirpi July 2015)



### Detection

Virtualization, sandbox, user activity, and related discovery techniques will likely occur in the first steps of an operation but may also occur throughout as an adversary learns the environment. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as lateral movement, based on the information obtained. Detecting actions related to virtualization and sandbox identification may be difficult depending on the adversary's implementation and monitoring required. Monitoring for suspicious processes being spawned that gather a variety of system information or perform other forms of Discovery, especially in a short period of time, may aid in detection.

### Defenses Bypassed

Anti-virus, Host forensic analysis, Signature-based detection, Static File Analysis

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
FROM "Detection Rules" AND #T1497
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1497
```
