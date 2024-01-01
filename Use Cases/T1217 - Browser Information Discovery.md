---
created: 2018-04-18
last_modified: 2023-04-16
version: 2.0
tactics: Discovery
url: https://attack.mitre.org/techniques/T1217
platforms: Linux, Windows, macOS
tags: [T1217, techniques, Discovery]
---

## Browser Information Discovery

### Description

Adversaries may enumerate information about browsers to learn more about compromised environments. Data saved by browsers (such as bookmarks, accounts, and browsing history) may reveal a variety of personal information about users (e.g., banking sites, relationships/interests, social media, etc.) as well as details about internal network resources such as servers, tools/dashboards, or other related infrastructure.(Citation: Kaspersky Autofill)

Browser information may also highlight additional targets after an adversary has access to valid credentials, especially [Credentials In Files](https://attack.mitre.org/techniques/T1552/001) associated with logins cached by a browser.

Specific storage locations vary based on platform and/or application, but browser information is typically stored in local files and databases (e.g., `%APPDATA%/Google/Chrome`).(Citation: Chrome Roaming Profiles)

### Detection

Monitor processes and command-line arguments for actions that could be taken to gather browser bookmark information. Remote access tools with built-in features may interact directly using APIs to gather information. Information may also be acquired through system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).

System and network discovery techniques normally occur throughout an operation as an adversary learns the environment. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as Collection and Exfiltration, based on the information obtained.

### Defenses Bypassed



### Data Sources

  - Command: Command Execution
  -  File: File Access
  -  Process: Process Creation
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1217
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1217
```
