---
created: 2019-04-08
last_modified: 2022-03-25
version: 1.3
tactics: Impact
url: https://attack.mitre.org/techniques/T1491
platforms: IaaS, Linux, Windows, macOS
tags: [T1491, techniques, Impact]
---

## Defacement

### Description

Adversaries may modify visual content available internally or externally to an enterprise network, thus affecting the integrity of the original content. Reasons for [Defacement](https://attack.mitre.org/techniques/T1491) include delivering messaging, intimidation, or claiming (possibly false) credit for an intrusion. Disturbing or offensive images may be used as a part of [Defacement](https://attack.mitre.org/techniques/T1491) in order to cause user discomfort, or to pressure compliance with accompanying messages. 


### Detection

Monitor internal and external websites for unplanned content changes. Monitor application logs for abnormal behavior that may indicate attempted or successful exploitation. Use deep packet inspection to look for artifacts of common exploit traffic, such as SQL injection. Web Application Firewalls may detect improper inputs attempting exploitation.



### Defenses Bypassed



### Data Sources

  - Application Log: Application Log Content
  -  File: File Creation
  -  File: File Modification
  -  Network Traffic: Network Traffic Content
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1491
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "Testing Runbooks" AND #T1491
```
