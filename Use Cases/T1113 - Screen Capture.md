---
created: 2017-05-31
last_modified: 2023-03-30
version: 1.1
tactics: Collection
url: https://attack.mitre.org/techniques/T1113
platforms: Linux, Windows, macOS
tags: [T1113, techniques, Collection]
---

## Screen Capture

### Description

Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation. Screen capturing functionality may be included as a feature of a remote access tool used in post-compromise operations. Taking a screenshot is also typically possible through native utilities or API calls, such as <code>CopyFromScreen</code>, <code>xwd</code>, or <code>screencapture</code>.(Citation: CopyFromScreen .NET)(Citation: Antiquated Mac Malware)


### Detection

Monitoring for screen capture behavior will depend on the method used to obtain data from the operating system and write output files. Detection methods could include collecting information from unusual processes using API calls used to obtain image data, and monitoring for image files written to disk. The sensor data may need to be correlated with other events to identify malicious activity, depending on the legitimacy of this behavior within a given network environment.

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
FROM "Detection Rules" AND #T1113
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1113
```
