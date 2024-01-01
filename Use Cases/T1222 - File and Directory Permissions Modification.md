---
created: 2018-10-17
last_modified: 2022-10-19
version: 2.2
tactics: Defense Evasion
url: https://attack.mitre.org/techniques/T1222
platforms: Linux, Windows, macOS
tags: [T1222, techniques, Defense_Evasion]
---

## File and Directory Permissions Modification

### Description

Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files.(Citation: Hybrid Analysis Icacls1 June 2018)(Citation: Hybrid Analysis Icacls2 May 2018) File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with the appropriate permissions. File and directory ACL implementations vary by platform, but generally explicitly designate which users or groups can perform which actions (read, write, execute, etc.).

Modifications may include changing specific access rights, which may require taking ownership of a file or directory and/or elevated permissions depending on the file or directory?s existing permissions. This may enable malicious activity such as modifying, replacing, or deleting specific files or directories. Specific file and directory modifications may be a required step for many techniques, such as establishing Persistence via [Accessibility Features](https://attack.mitre.org/techniques/T1546/008), [Boot or Logon Initialization Scripts](https://attack.mitre.org/techniques/T1037), [Unix Shell Configuration Modification](https://attack.mitre.org/techniques/T1546/004), or tainting/hijacking other instrumental binary/configuration files via [Hijack Execution Flow](https://attack.mitre.org/techniques/T1574).

Adversaries may also change permissions of symbolic links. For example, malware (particularly ransomware) may modify symbolic links and associated settings to enable access to files from local shortcuts with remote paths.(Citation: new_rust_based_ransomware)(Citation: bad_luck_blackcat)(Citation: falconoverwatch_blackcat_attack)(Citation: blackmatter_blackcat)(Citation: fsutil_behavior) 

### Detection

Monitor and investigate attempts to modify ACLs and file/directory ownership. Many of the commands used to modify ACLs and file/directory ownership are built-in system utilities and may generate a high false positive alert rate, so compare against baseline knowledge for how systems are typically used and correlate modification events with other indications of malicious activity where possible.

Consider enabling file/directory permission change auditing on folders containing key binary/configuration files. For example, Windows Security Log events (Event ID 4670) are created when DACLs are modified.(Citation: EventTracker File Permissions Feb 2014)

### Defenses Bypassed

File system access controls

### Data Sources

  - Active Directory: Active Directory Object Modification
  -  Command: Command Execution
  -  File: File Metadata
  -  Process: Process Creation
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1222
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1222
```
