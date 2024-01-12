---
created: 2021-08-06
last_modified: 2023-01-06
version: 1.1
tactics: Discovery
url: https://attack.mitre.org/techniques/T1615
platforms: Windows
tags: [T1615, techniques, Discovery]
---

## Group Policy Discovery

### Description

Adversaries may gather information on Group Policy settings to identify paths for privilege escalation, security measures applied within a domain, and to discover patterns in domain objects that can be manipulated or used to blend in the environment. Group Policy allows for centralized management of user and computer settings in Active Directory (AD). Group policy objects (GPOs) are containers for group policy settings made up of files stored within a predictable network path `\<DOMAIN>\SYSVOL\<DOMAIN>\Policies\`.(Citation: TechNet Group Policy Basics)(Citation: ADSecurity GPO Persistence 2016)

Adversaries may use commands such as <code>gpresult</code> or various publicly available PowerShell functions, such as <code>Get-DomainGPO</code> and <code>Get-DomainGPOLocalGroup</code>, to gather information on Group Policy settings.(Citation: Microsoft gpresult)(Citation: Github PowerShell Empire) Adversaries may use this information to shape follow-on behaviors, including determining potential attack paths within the target network as well as opportunities to manipulate Group Policy settings (i.e. [Domain Policy Modification](https://attack.mitre.org/techniques/T1484)) for their benefit.

### Detection

System and network discovery techniques normally occur throughout an operation as an adversary learns the environment. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities based on the information obtained.

Monitor for suspicious use of <code>gpresult</code>. Monitor for the use of PowerShell functions such as <code>Get-DomainGPO</code> and <code>Get-DomainGPOLocalGroup</code> and processes spawning with command-line arguments containing <code>GPOLocalGroup</code>.

Monitor for abnormal LDAP queries with filters for <code>groupPolicyContainer</code> and high volumes of LDAP traffic to domain controllers. Windows Event ID 4661 can also be used to detect when a directory service has been accessed.

### Defenses Bypassed



### Data Sources

  - Active Directory: Active Directory Object Access
  -  Command: Command Execution
  -  Network Traffic: Network Traffic Content
  -  Process: Process Creation
  -  Script: Script Execution
### Detection Rule

```query
tag: detection_rule
tag: T1615
```

### Rule Testing

```query
tag: atomic_test
tag: T1615
```
