---
created: 2023-03-13
last_modified: 2023-04-14
version: 1.0
tactics: Execution
url: https://attack.mitre.org/techniques/T1651
platforms: Azure AD, IaaS
tags: [T1651, techniques, Execution]
---

## Cloud Administration Command

### Description

Adversaries may abuse cloud management services to execute commands within virtual machines or hybrid-joined devices. Resources such as AWS Systems Manager, Azure RunCommand, and Runbooks allow users to remotely run scripts in virtual machines by leveraging installed virtual machine agents. Similarly, in Azure AD environments, Microsoft Endpoint Manager allows Global or Intune Administrators to run scripts as SYSTEM on on-premises devices joined to the Azure AD.(Citation: AWS Systems Manager Run Command)(Citation: Microsoft Run Command)(Citation: SpecterOps Lateral Movement from Azure to On-Prem AD 2020)

If an adversary gains administrative access to a cloud environment, they may be able to abuse cloud management services to execute commands in the environment?s virtual machines or on-premises hybrid-joined devices. Additionally, an adversary that compromises a service provider or delegated administrator account may similarly be able to leverage a [Trusted Relationship](https://attack.mitre.org/techniques/T1199) to execute commands in connected virtual machines.(Citation: MSTIC Nobelium Oct 2021)

### Detection



### Defenses Bypassed



### Data Sources

  - Command: Command Execution
  -  Process: Process Creation
  -  Script: Script Execution
### Detection Rule

```query
tag: detection_rule
tag: T1651
```

### Rule Testing

```query
tag: atomic_test
tag: T1651
```
