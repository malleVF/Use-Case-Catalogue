---
created: 2023-03-28
last_modified: 2023-05-04
version: 1.0
tactics: Discovery
url: https://attack.mitre.org/techniques/T1652
platforms: Linux, Windows, macOS
tags: [T1652, techniques, Discovery]
---

## Device Driver Discovery

### Description

Adversaries may attempt to enumerate local device drivers on a victim host. Information about device drivers may highlight various insights that shape follow-on behaviors, such as the function/purpose of the host, present security tools (i.e. [Security Software Discovery](https://attack.mitre.org/techniques/T1518/001)) or other defenses (e.g., [Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497)), as well as potential exploitable vulnerabilities (e.g., [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)).

Many OS utilities may provide information about local device drivers, such as `driverquery.exe` and the `EnumDeviceDrivers()` API function on Windows.(Citation: Microsoft Driverquery)(Citation: Microsoft EnumDeviceDrivers) Information about device drivers (as well as associated services, i.e., [System Service Discovery](https://attack.mitre.org/techniques/T1007)) may also be available in the Registry.(Citation: Microsoft Registry Drivers)

On Linux/macOS, device drivers (in the form of kernel modules) may be visible within `/dev` or using utilities such as `lsmod` and `modinfo`.(Citation: Linux Kernel Programming)(Citation: lsmod man)(Citation: modinfo man)

### Detection



### Defenses Bypassed



### Data Sources

  - Command: Command Execution
  -  Process: OS API Execution
  -  Process: Process Creation
  -  Windows Registry: Windows Registry Key Access
### Detection Rule

```query
tag: detection_rule
tag: T1652
```

### Rule Testing

```query
tag: atomic_test
tag: T1652
```
