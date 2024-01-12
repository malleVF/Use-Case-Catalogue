---
created: 2017-05-31
last_modified: 2023-10-16
version: 2.6
tactics: Persistence, Privilege Escalation
url: https://attack.mitre.org/techniques/T1098
platforms: Azure AD, Containers, Google Workspace, IaaS, Linux, Network, Office 365, SaaS, Windows, macOS
tags: [T1098, techniques, Persistence,_Privilege_Escalation]
---

## Account Manipulation

### Description

Adversaries may manipulate accounts to maintain and/or elevate access to victim systems. Account manipulation may consist of any action that preserves or modifies adversary access to a compromised account, such as modifying credentials or permission groups. These actions could also include account activity designed to subvert security policies, such as performing iterative password updates to bypass password duration policies and preserve the life of compromised credentials. 

In order to create or manipulate accounts, the adversary must already have sufficient permissions on systems or the domain. However, account manipulation may also lead to privilege escalation where modifications grant access to additional roles, permissions, or higher-privileged [Valid Accounts](https://attack.mitre.org/techniques/T1078).

### Detection

Collect events that correlate with changes to account objects and/or permissions on systems and the domain, such as event IDs 4738, 4728 and 4670.(Citation: Microsoft User Modified Event)(Citation: Microsoft Security Event 4670)(Citation: Microsoft Security Event 4670) Monitor for modification of accounts in correlation with other suspicious activity. Changes may occur at unusual times or from unusual systems. Especially flag events where the subject and target accounts differ(Citation: InsiderThreat ChangeNTLM July 2017) or that include additional flags such as changing a password without knowledge of the old password.(Citation: GitHub Mimikatz Issue 92 June 2017)

Monitor for use of credentials at unusual times or to unusual systems or services. This may also correlate with other suspicious activity.

Monitor for unusual permissions changes that may indicate excessively broad permissions being granted to compromised accounts. However, account manipulation may also lead to privilege escalation where modifications grant access to additional roles, permissions, or higher-privileged [Valid Accounts](https://attack.mitre.org/techniques/T1078)

### Defenses Bypassed



### Data Sources

  - Active Directory: Active Directory Object Modification
  -  Command: Command Execution
  -  File: File Modification
  -  Group: Group Modification
  -  Process: Process Creation
  -  User Account: User Account Modification
### Detection Rule

```query
tag: detection_rule
tag: T1098
```

### Rule Testing

```query
tag: atomic_test
tag: T1098
```
