---
created: 2019-02-14
last_modified: 2022-06-16
version: 1.2
tactics: Discovery
url: https://attack.mitre.org/techniques/T1482
platforms: Windows
tags: [T1482, techniques, Discovery]
---

## Domain Trust Discovery

### Description

Adversaries may attempt to gather information on domain trust relationships that may be used to identify lateral movement opportunities in Windows multi-domain/forest environments. Domain trusts provide a mechanism for a domain to allow access to resources based on the authentication procedures of another domain.(Citation: Microsoft Trusts) Domain trusts allow the users of the trusted domain to access resources in the trusting domain. The information discovered may help the adversary conduct [SID-History Injection](https://attack.mitre.org/techniques/T1134/005), [Pass the Ticket](https://attack.mitre.org/techniques/T1550/003), and [Kerberoasting](https://attack.mitre.org/techniques/T1558/003).(Citation: AdSecurity Forging Trust Tickets)(Citation: Harmj0y Domain Trusts) Domain trusts can be enumerated using the `DSEnumerateDomainTrusts()` Win32 API call, .NET methods, and LDAP.(Citation: Harmj0y Domain Trusts) The Windows utility [Nltest](https://attack.mitre.org/software/S0359) is known to be used by adversaries to enumerate domain trusts.(Citation: Microsoft Operation Wilysupply)

### Detection

System and network discovery techniques normally occur throughout an operation as an adversary learns the environment. Data and events should not be viewed in isolation but as part of a chain of behavior that could lead to other activities based on the information obtained.

Monitor processes and command-line arguments for actions that could be taken to gather system and network information, such as `nltest /domain_trusts`. Remote access tools with built-in features may interact directly with the Windows API to gather information. Look for the `DSEnumerateDomainTrusts()` Win32 API call to spot activity associated with [Domain Trust Discovery](https://attack.mitre.org/techniques/T1482).(Citation: Harmj0y Domain Trusts) Information may also be acquired through Windows system management tools such as [PowerShell](https://attack.mitre.org/techniques/T1059/001). The .NET method `GetAllTrustRelationships()` can be an indicator of [Domain Trust Discovery](https://attack.mitre.org/techniques/T1482).(Citation: Microsoft GetAllTrustRelationships)


### Defenses Bypassed



### Data Sources

  - Command: Command Execution
  -  Network Traffic: Network Traffic Content
  -  Process: OS API Execution
  -  Process: Process Creation
  -  Script: Script Execution
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1482
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "Testing Runbooks" AND #T1482
```
