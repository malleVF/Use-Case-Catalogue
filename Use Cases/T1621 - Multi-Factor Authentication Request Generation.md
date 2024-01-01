---
created: 2022-04-01
last_modified: 2023-04-04
version: 1.0
tactics: Credential Access
url: https://attack.mitre.org/techniques/T1621
platforms: Azure AD, Google Workspace, IaaS, Linux, Office 365, SaaS, Windows, macOS
tags: [T1621, techniques, Credential_Access]
---

## Multi-Factor Authentication Request Generation

### Description

Adversaries may attempt to bypass multi-factor authentication (MFA) mechanisms and gain access to accounts by generating MFA requests sent to users.

Adversaries in possession of credentials to [Valid Accounts](https://attack.mitre.org/techniques/T1078) may be unable to complete the login process if they lack access to the 2FA or MFA mechanisms required as an additional credential and security control. To circumvent this, adversaries may abuse the automatic generation of push notifications to MFA services such as Duo Push, Microsoft Authenticator, Okta, or similar services to have the user grant access to their account.

In some cases, adversaries may continuously repeat login attempts in order to bombard users with MFA push notifications, SMS messages, and phone calls, potentially resulting in the user finally accepting the authentication request in response to ?MFA fatigue.?(Citation: Russian 2FA Push Annoyance - Cimpanu)(Citation: MFA Fatigue Attacks - PortSwigger)(Citation: Suspected Russian Activity Targeting Government and Business Entities Around the Globe)

### Detection

Monitor user account logs as well as 2FA/MFA application logs for suspicious events: unusual login attempt source location, mismatch in location of login attempt and smart device receiving 2FA/MFA request prompts, and high volume of repeated login attempts, all of which may indicate user's primary credentials have been compromised minus 2FA/MFA mechanism. 

### Defenses Bypassed



### Data Sources

  - Application Log: Application Log Content
  -  Logon Session: Logon Session Creation
  -  Logon Session: Logon Session Metadata
  -  User Account: User Account Authentication
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1621
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1621
```
