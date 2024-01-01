---
created: 2018-01-16
last_modified: 2022-02-25
version: 2.0
tactics: Collection
url: https://attack.mitre.org/techniques/T1185
platforms: Windows
tags: [T1185, techniques, Collection]
---

## Browser Session Hijacking

### Description

Adversaries may take advantage of security vulnerabilities and inherent functionality in browser software to change content, modify user-behaviors, and intercept information as part of various browser session hijacking techniques.(Citation: Wikipedia Man in the Browser)

A specific example is when an adversary injects software into a browser that allows them to inherit cookies, HTTP sessions, and SSL client certificates of a user then use the browser as a way to pivot into an authenticated intranet.(Citation: Cobalt Strike Browser Pivot)(Citation: ICEBRG Chrome Extensions) Executing browser-based behaviors such as pivoting may require specific process permissions, such as <code>SeDebugPrivilege</code> and/or high-integrity/administrator rights.

Another example involves pivoting browser traffic from the adversary's browser through the user's browser by setting up a proxy which will redirect web traffic. This does not alter the user's traffic in any way, and the proxy connection can be severed as soon as the browser is closed. The adversary assumes the security context of whichever browser process the proxy is injected into. Browsers typically create a new process for each tab that is opened and permissions and certificates are separated accordingly. With these permissions, an adversary could potentially browse to any resource on an intranet, such as [Sharepoint](https://attack.mitre.org/techniques/T1213/002) or webmail, that is accessible through the browser and which the browser has sufficient permissions. Browser pivoting may also bypass security provided by 2-factor authentication.(Citation: cobaltstrike manual)

### Detection

This may be a difficult technique to detect because adversary traffic may be masked by normal user traffic. New processes may not be created and no additional software dropped to disk. Authentication logs can be used to audit logins to specific web applications, but determining malicious logins versus benign logins may be difficult if activity matches typical user behavior. Monitor for [Process Injection](https://attack.mitre.org/techniques/T1055) against browser applications.

### Defenses Bypassed



### Data Sources

  - Logon Session: Logon Session Creation
  -  Process: Process Access
  -  Process: Process Modification
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1185
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1185
```
