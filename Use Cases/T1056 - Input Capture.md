---
created: 2017-05-31
last_modified: 2023-03-30
version: 1.2
tactics: Collection, Credential Access
url: https://attack.mitre.org/techniques/T1056
platforms: Linux, Network, Windows, macOS
tags: [T1056, techniques, Collection,Credential_Access]
---

## Input Capture

### Description

Adversaries may use methods of capturing user input to obtain credentials or collect information. During normal system usage, users often provide credentials to various different locations, such as login pages/portals or system dialog boxes. Input capture mechanisms may be transparent to the user (e.g. [Credential API Hooking](https://attack.mitre.org/techniques/T1056/004)) or rely on deceiving the user into providing input into what they believe to be a genuine service (e.g. [Web Portal Capture](https://attack.mitre.org/techniques/T1056/003)).

### Detection

Detection may vary depending on how input is captured but may include monitoring for certain Windows API calls (e.g. `SetWindowsHook`, `GetKeyState`, and `GetAsyncKeyState`)(Citation: Adventures of a Keystroke), monitoring for malicious instances of [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059), and ensuring no unauthorized drivers or kernel modules that could indicate keylogging or API hooking are present.

### Defenses Bypassed



### Data Sources

  - Driver: Driver Load
  -  File: File Modification
  -  Process: OS API Execution
  -  Process: Process Creation
  -  Process: Process Metadata
  -  Windows Registry: Windows Registry Key Modification
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1056
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1056
```
