---
created: 2017-05-31
last_modified: 2023-04-14
version: 1.2
tactics: Collection
url: https://attack.mitre.org/techniques/T1115
platforms: Linux, Windows, macOS
tags: [T1115, techniques, Collection]
---

## Clipboard Data

### Description

Adversaries may collect data stored in the clipboard from users copying information within or between applications. 

For example, on Windows adversaries can access clipboard data by using <code>clip.exe</code> or <code>Get-Clipboard</code>.(Citation: MSDN Clipboard)(Citation: clip_win_server)(Citation: CISA_AA21_200B) Additionally, adversaries may monitor then replace users? clipboard with their data (e.g., [Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002)).(Citation: mining_ruby_reversinglabs)

macOS and Linux also have commands, such as <code>pbpaste</code>, to grab clipboard contents.(Citation: Operating with EmPyre)

### Detection

Access to the clipboard is a legitimate function of many applications on an operating system. If an organization chooses to monitor for this behavior, then the data will likely need to be correlated against other suspicious or non-user-driven activity.

### Defenses Bypassed



### Data Sources

  - Command: Command Execution
  -  Process: OS API Execution
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1115
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1115
```
