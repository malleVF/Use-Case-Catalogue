---
created: 2018-04-18
last_modified: 2022-04-18
version: 2.0
tactics: Defense Evasion
url: https://attack.mitre.org/techniques/T1216
platforms: Windows
tags: [T1216, techniques, Defense_Evasion]
---

## System Script Proxy Execution

### Description

Adversaries may use trusted scripts, often signed with certificates, to proxy the execution of malicious files. Several Microsoft signed scripts that have been downloaded from Microsoft or are default on Windows installations can be used to proxy execution of other files.(Citation: LOLBAS Project) This behavior may be abused by adversaries to execute malicious files that could bypass application control and signature validation on systems.(Citation: GitHub Ultimate AppLocker Bypass List)

### Detection

Monitor script processes, such as `cscript`, and command-line parameters for scripts like PubPrn.vbs that may be used to proxy execution of malicious files.

### Defenses Bypassed

Application control, Digital Certificate Validation

### Data Sources

  - Command: Command Execution
  -  Process: Process Creation
  -  Script: Script Execution
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1216
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "Testing Runbooks" AND #T1216
```
