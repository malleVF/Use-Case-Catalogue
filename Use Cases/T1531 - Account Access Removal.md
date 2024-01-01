---
created: 2019-10-09
last_modified: 2023-03-22
version: 1.2
tactics: Impact
url: https://attack.mitre.org/techniques/T1531
platforms: Linux, Office 365, SaaS, Windows, macOS
tags: [T1531, techniques, Impact]
---

## Account Access Removal

### Description

Adversaries may interrupt availability of system and network resources by inhibiting access to accounts utilized by legitimate users. Accounts may be deleted, locked, or manipulated (ex: changed credentials) to remove access to accounts. Adversaries may also subsequently log off and/or perform a [System Shutdown/Reboot](https://attack.mitre.org/techniques/T1529) to set malicious changes into place.(Citation: CarbonBlack LockerGoga 2019)(Citation: Unit42 LockerGoga 2019)

In Windows, [Net](https://attack.mitre.org/software/S0039) utility, <code>Set-LocalUser</code> and <code>Set-ADAccountPassword</code> [PowerShell](https://attack.mitre.org/techniques/T1059/001) cmdlets may be used by adversaries to modify user accounts. In Linux, the <code>passwd</code> utility may be used to change passwords. Accounts could also be disabled by Group Policy. 

Adversaries who use ransomware or similar attacks may first perform this and other Impact behaviors, such as [Data Destruction](https://attack.mitre.org/techniques/T1485) and [Defacement](https://attack.mitre.org/techniques/T1491), in order to impede incident response/recovery before completing the [Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486) objective. 

### Detection

Use process monitoring to monitor the execution and command line parameters of binaries involved in deleting accounts or changing passwords, such as use of [Net](https://attack.mitre.org/software/S0039). Windows event logs may also designate activity associated with an adversary's attempt to remove access to an account:

* Event ID 4723 - An attempt was made to change an account's password
* Event ID 4724 - An attempt was made to reset an account's password
* Event ID 4726 - A user account was deleted
* Event ID 4740 - A user account was locked out

Alerting on [Net](https://attack.mitre.org/software/S0039) and these Event IDs may generate a high degree of false positives, so compare against baseline knowledge for how systems are typically used and correlate modification events with other indications of malicious activity where possible.

### Defenses Bypassed



### Data Sources

  - Active Directory: Active Directory Object Modification
  -  User Account: User Account Deletion
  -  User Account: User Account Modification
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1531
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1531
```
