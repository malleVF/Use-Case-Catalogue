---
created: 2017-05-31
last_modified: 2023-04-15
version: 2.4
tactics: Discovery
url: https://attack.mitre.org/techniques/T1087
platforms: Azure AD, Google Workspace, IaaS, Linux, Office 365, SaaS, Windows, macOS
tags: [T1087, techniques, Discovery]
---

## Account Discovery

### Description

Adversaries may attempt to get a listing of valid accounts, usernames, or email addresses on a system or within a compromised environment. This information can help adversaries determine which accounts exist, which can aid in follow-on behavior such as brute-forcing, spear-phishing attacks, or account takeovers (e.g., [Valid Accounts](https://attack.mitre.org/techniques/T1078)).

Adversaries may use several methods to enumerate accounts, including abuse of existing tools, built-in commands, and potential misconfigurations that leak account names and roles or permissions in the targeted environment.

For examples, cloud environments typically provide easily accessible interfaces to obtain user lists. On hosts, adversaries can use default [PowerShell](https://attack.mitre.org/techniques/T1059/001) and other command line functionality to identify accounts. Information about email addresses and accounts may also be extracted by searching an infected system?s files.

### Detection

System and network discovery techniques normally occur throughout an operation as an adversary learns the environment. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as Lateral Movement, based on the information obtained.

Monitor processes and command-line arguments for actions that could be taken to gather system and network information. Remote access tools with built-in features may interact directly with the Windows API to gather information. Information may also be acquired through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).

Monitor for processes that can be used to enumerate user accounts, such as <code>net.exe</code> and <code>net1.exe</code>, especially when executed in quick succession.(Citation: Elastic - Koadiac Detection with EQL)

### Defenses Bypassed



### Data Sources

  - Command: Command Execution
  -  File: File Access
  -  Process: Process Creation
### Detection Rule

```query
tag: detection_rule
tag: T1087
```

### Rule Testing

```query
tag: atomic_test
tag: T1087
```
