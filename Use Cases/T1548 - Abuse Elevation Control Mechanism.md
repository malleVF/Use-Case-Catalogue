---
created: 2020-01-30
last_modified: 2023-10-02
version: 1.2
tactics: Defense Evasion, Privilege Escalation
url: https://attack.mitre.org/techniques/T1548
platforms: Azure AD, Google Workspace, IaaS, Linux, Office 365, Windows, macOS
tags: [T1548, techniques, Defense_Evasion,Privilege_Escalation]
---

## Abuse Elevation Control Mechanism

### Description

Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions. Most modern systems contain native elevation control mechanisms that are intended to limit privileges that a user can perform on a machine. Authorization has to be granted to specific users in order to perform tasks that can be considered of higher risk. An adversary can perform several methods to take advantage of built-in control mechanisms in order to escalate privileges on a system.

### Detection

Monitor the file system for files that have the setuid or setgid bits set. Also look for any process API calls for behavior that may be indicative of [Process Injection](https://attack.mitre.org/techniques/T1055) and unusual loaded DLLs through [DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1574/001), which indicate attempts to gain access to higher privileged processes. On Linux, auditd can alert every time a user's actual ID and effective ID are different (this is what happens when you sudo).

Consider monitoring for <code>/usr/libexec/security_authtrampoline</code> executions which may indicate that AuthorizationExecuteWithPrivileges is being executed. MacOS system logs may also indicate when AuthorizationExecuteWithPrivileges is being called. Monitoring OS API callbacks for the execution can also be a way to detect this behavior but requires specialized security tooling.

On Linux, auditd can alert every time a user's actual ID and effective ID are different (this is what happens when you sudo). This technique is abusing normal functionality in macOS and Linux systems, but sudo has the ability to log all input and output based on the <code>LOG_INPUT</code> and <code>LOG_OUTPUT</code> directives in the <code>/etc/sudoers</code> file.

There are many ways to perform UAC bypasses when a user is in the local administrator group on a system, so it may be difficult to target detection on all variations. Efforts should likely be placed on mitigation and collecting enough information on process launches and actions that could be performed before and after a UAC bypass is performed. Some UAC bypass methods rely on modifying specific, user-accessible Registry settings. Analysts should monitor Registry settings for unauthorized changes.

### Defenses Bypassed



### Data Sources

  - Command: Command Execution
  -  File: File Metadata
  -  File: File Modification
  -  Process: OS API Execution
  -  Process: Process Creation
  -  Process: Process Metadata
  -  User Account: User Account Modification
  -  Windows Registry: Windows Registry Key Modification
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1548
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1548
```
