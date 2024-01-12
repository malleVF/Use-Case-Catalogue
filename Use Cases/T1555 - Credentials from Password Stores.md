---
created: 2020-02-11
last_modified: 2023-09-30
version: 1.1
tactics: Credential Access
url: https://attack.mitre.org/techniques/T1555
platforms: IaaS, Linux, Windows, macOS
tags: [T1555, techniques, Credential_Access]
---

## Credentials from Password Stores

### Description

Adversaries may search for common password storage locations to obtain user credentials. Passwords are stored in several places on a system, depending on the operating system or application holding the credentials. There are also specific applications and services that store passwords to make them easier for users to manage and maintain, such as password managers and cloud secrets vaults. Once credentials are obtained, they can be used to perform lateral movement and access restricted information.

### Detection

Monitor system calls, file read events, and processes for suspicious activity that could indicate searching for a password  or other activity related to performing keyword searches (e.g. password, pwd, login, store, secure, credentials, etc.) in process memory for credentials. File read events should be monitored surrounding known password storage applications.

### Defenses Bypassed



### Data Sources

  - Cloud Service: Cloud Service Enumeration
  -  Command: Command Execution
  -  File: File Access
  -  Process: OS API Execution
  -  Process: Process Access
  -  Process: Process Creation
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1555
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "Testing Runbooks" AND #T1555
```
