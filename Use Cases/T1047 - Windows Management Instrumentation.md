---
created: 2017-05-31
last_modified: 2023-07-24
version: 1.4
tactics: Execution
url: https://attack.mitre.org/techniques/T1047
platforms: Windows
tags: [T1047, techniques, Execution]
---

## Windows Management Instrumentation

### Description

Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands and payloads. WMI is an administration feature that provides a uniform environment to access Windows system components. The WMI service enables both local and remote access, though the latter is facilitated by [Remote Services](https://attack.mitre.org/techniques/T1021) such as [Distributed Component Object Model](https://attack.mitre.org/techniques/T1021/003) (DCOM) and [Windows Remote Management](https://attack.mitre.org/techniques/T1021/006) (WinRM).(Citation: MSDN WMI) Remote WMI over DCOM operates using port 135, whereas WMI over WinRM operates over port 5985 when using HTTP and 5986 for HTTPS.(Citation: MSDN WMI)(Citation: FireEye WMI 2015)

An adversary can use WMI to interact with local and remote systems and use it as a means to execute various behaviors, such as gathering information for Discovery as well as remote Execution of files as part of Lateral Movement. (Citation: FireEye WMI SANS 2015) (Citation: FireEye WMI 2015)

### Detection

Monitor network traffic for WMI connections; the use of WMI in environments that do not typically use WMI may be suspect. Perform process monitoring to capture command-line arguments of "wmic" and detect commands that are used to perform remote behavior. (Citation: FireEye WMI 2015)

### Defenses Bypassed



### Data Sources

  - Command: Command Execution
  -  Network Traffic: Network Connection Creation
  -  Process: Process Creation
  -  WMI: WMI Creation
### Detection Rule

```query
tag: detection_rule
tag: T1047
```

### Rule Testing

```query
tag: atomic_test
tag: T1047
```
