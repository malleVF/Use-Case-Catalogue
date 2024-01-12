---
created: 2020-02-25
last_modified: 2020-03-23
version: 1.0
tactics: Lateral Movement
url: https://attack.mitre.org/techniques/T1563
platforms: Linux, Windows, macOS
tags: [T1563, techniques, Lateral_Movement]
---

## Remote Service Session Hijacking

### Description

Adversaries may take control of preexisting sessions with remote services to move laterally in an environment. Users may use valid credentials to log into a service specifically designed to accept remote connections, such as telnet, SSH, and RDP. When a user logs into a service, a session will be established that will allow them to maintain a continuous interaction with that service.

Adversaries may commandeer these sessions to carry out actions on remote systems. [Remote Service Session Hijacking](https://attack.mitre.org/techniques/T1563) differs from use of [Remote Services](https://attack.mitre.org/techniques/T1021) because it hijacks an existing session rather than creating a new session using [Valid Accounts](https://attack.mitre.org/techniques/T1078).(Citation: RDP Hijacking Medium)(Citation: Breach Post-mortem SSH Hijack)

### Detection

Use of these services may be legitimate, depending upon the network environment and how it is used. Other factors, such as access patterns and activity that occurs after a remote login, may indicate suspicious or malicious behavior with that service. Monitor for user accounts logged into systems they would not normally access or access patterns to multiple systems over a relatively short period of time.

Monitor for processes and command-line arguments associated with hijacking service sessions.

### Defenses Bypassed



### Data Sources

  - Command: Command Execution
  -  Logon Session: Logon Session Creation
  -  Network Traffic: Network Traffic Content
  -  Network Traffic: Network Traffic Flow
  -  Process: Process Creation
### Detection Rule

```query
tag: detection_rule
tag: T1563
```

### Rule Testing

```query
tag: atomic_test
tag: T1563
```
