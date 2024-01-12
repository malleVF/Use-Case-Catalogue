---
created: 2017-05-31
last_modified: 2023-04-14
version: 2.1
tactics: Credential Access
url: https://attack.mitre.org/techniques/T1111
platforms: Linux, Windows, macOS
tags: [T1111, techniques, Credential_Access]
---

## Multi-Factor Authentication Interception

### Description

Adversaries may target multi-factor authentication (MFA) mechanisms, (i.e., smart cards, token generators, etc.) to gain access to credentials that can be used to access systems, services, and network resources. Use of MFA is recommended and provides a higher level of security than usernames and passwords alone, but organizations should be aware of techniques that could be used to intercept and bypass these security mechanisms. 

If a smart card is used for multi-factor authentication, then a keylogger will need to be used to obtain the password associated with a smart card during normal use. With both an inserted card and access to the smart card password, an adversary can connect to a network resource using the infected system to proxy the authentication with the inserted hardware token. (Citation: Mandiant M Trends 2011)

Adversaries may also employ a keylogger to similarly target other hardware tokens, such as RSA SecurID. Capturing token input (including a user's personal identification code) may provide temporary access (i.e. replay the one-time passcode until the next value rollover) as well as possibly enabling adversaries to reliably predict future authentication values (given access to both the algorithm and any seed values used to generate appended temporary codes). (Citation: GCN RSA June 2011)

Other methods of MFA may be intercepted and used by an adversary to authenticate. It is common for one-time codes to be sent via out-of-band communications (email, SMS). If the device and/or service is not secured, then it may be vulnerable to interception. Service providers can also be targeted: for example, an adversary may compromise an SMS messaging service in order to steal MFA codes sent to users? phones.(Citation: Okta Scatter Swine 2022)

### Detection

Detecting use of proxied smart card connections by an adversary may be difficult because it requires the token to be inserted into a system; thus it is more likely to be in use by a legitimate user and blend in with other network behavior.

Similar to [Input Capture](https://attack.mitre.org/techniques/T1056), keylogging activity can take various forms but can may be detected via installation of a driver, setting a hook, or usage of particular API calls associated with polling to intercept keystrokes.

### Defenses Bypassed



### Data Sources

  - Driver: Driver Load
  -  Process: OS API Execution
  -  Windows Registry: Windows Registry Key Modification
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1111
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "Testing Runbooks" AND #T1111
```
