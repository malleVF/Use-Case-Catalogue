---
created: 2019-03-07
last_modified: 2021-02-09
version: 2.0
tactics: Defense Evasion, Privilege Escalation
url: https://attack.mitre.org/techniques/T1484
platforms: Azure AD, Windows
tags: [T1484, techniques, Defense_Evasion,_Privilege_Escalation]
---

## Domain Policy Modification

### Description

Adversaries may modify the configuration settings of a domain to evade defenses and/or escalate privileges in domain environments. Domains provide a centralized means of managing how computer resources (ex: computers, user accounts) can act, and interact with each other, on a network. The policy of the domain also includes configuration settings that may apply between domains in a multi-domain/forest environment. Modifications to domain settings may include altering domain Group Policy Objects (GPOs) or changing trust settings for domains, including federation trusts.

With sufficient permissions, adversaries can modify domain policy settings. Since domain configuration settings control many of the interactions within the Active Directory (AD) environment, there are a great number of potential attacks that can stem from this abuse. Examples of such abuse include modifying GPOs to push a malicious [Scheduled Task](https://attack.mitre.org/techniques/T1053/005) to computers throughout the domain environment(Citation: ADSecurity GPO Persistence 2016)(Citation: Wald0 Guide to GPOs)(Citation: Harmj0y Abusing GPO Permissions) or modifying domain trusts to include an adversary controlled domain where they can control access tokens that will subsequently be accepted by victim domain resources.(Citation: Microsoft - Customer Guidance on Recent Nation-State Cyber Attacks) Adversaries can also change configuration settings within the AD environment to implement a [Rogue Domain Controller](https://attack.mitre.org/techniques/T1207).

Adversaries may temporarily modify domain policy, carry out a malicious action(s), and then revert the change to remove suspicious indicators.

### Detection

It may be possible to detect domain policy modifications using Windows event logs. Group policy modifications, for example, may be logged under a variety of Windows event IDs for modifying, creating, undeleting, moving, and deleting directory service objects (Event ID 5136, 5137, 5138, 5139, 5141 respectively). Monitor for modifications to domain trust settings, such as when a user or application modifies the federation settings on the domain or updates domain authentication from Managed to Federated via ActionTypes <code>Set federation settings on domain</code> and <code>Set domain authentication</code>.(Citation: Microsoft - Azure Sentinel ADFSDomainTrustMods)(Citation: Microsoft 365 Defender Solorigate) This may also include monitoring for Event ID 307 which can be correlated to relevant Event ID 510 with the same Instance ID for change details.(Citation: Sygnia Golden SAML)(Citation: CISA SolarWinds Cloud Detection)

Consider monitoring for commands/cmdlets and command-line arguments that may be leveraged to modify domain policy settings.(Citation: Microsoft - Update or Repair Federated domain) Some domain policy modifications, such as changes to federation settings, are likely to be rare.(Citation: Microsoft 365 Defender Solorigate)

### Defenses Bypassed

File system access controls, System access controls

### Data Sources

  - Active Directory: Active Directory Object Creation
  -  Active Directory: Active Directory Object Deletion
  -  Active Directory: Active Directory Object Modification
  -  Command: Command Execution
### Detection Rule

```query
tag: detection_rule
tag: T1484
```

### Rule Testing

```query
tag: atomic_test
tag: T1484
```
