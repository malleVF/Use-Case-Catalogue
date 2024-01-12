---
created: 2017-05-31
last_modified: 2023-08-14
version: 1.4
tactics: Defense Evasion
url: https://attack.mitre.org/techniques/T1112
platforms: Windows
tags: [T1112, techniques, Defense_Evasion]
---

## Modify Registry

### Description

Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.

Access to specific areas of the Registry depends on account permissions, some requiring administrator-level access. The built-in Windows command-line utility [Reg](https://attack.mitre.org/software/S0075) may be used for local or remote Registry modification. (Citation: Microsoft Reg) Other tools may also be used, such as a remote access tool, which may contain functionality to interact with the Registry through the Windows API.

Registry modifications may also include actions to hide keys, such as prepending key names with a null character, which will cause an error and/or be ignored when read via [Reg](https://attack.mitre.org/software/S0075) or other utilities using the Win32 API. (Citation: Microsoft Reghide NOV 2006) Adversaries may abuse these pseudo-hidden keys to conceal payloads/commands used to maintain persistence. (Citation: TrendMicro POWELIKS AUG 2014) (Citation: SpectorOps Hiding Reg Jul 2017)

The Registry of a remote system may be modified to aid in execution of files as part of lateral movement. It requires the remote Registry service to be running on the target system. (Citation: Microsoft Remote) Often [Valid Accounts](https://attack.mitre.org/techniques/T1078) are required, along with access to the remote system's [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002) for RPC communication.

### Detection

Modifications to the Registry are normal and occur throughout typical use of the Windows operating system. Consider enabling Registry Auditing on specific keys to produce an alertable event (Event ID 4657) whenever a value is changed (though this may not trigger when values are created with Reghide or other evasive methods). (Citation: Microsoft 4657 APR 2017) Changes to Registry entries that load software on Windows startup that do not correlate with known software, patch cycles, etc., are suspicious, as are additions or changes to files within the startup folder. Changes could also include new services and modification of existing binary paths to point to malicious files. If a change to a service-related entry occurs, then it will likely be followed by a local or remote service start or restart to execute the file.

Monitor processes and command-line arguments for actions that could be taken to change or delete information in the Registry. Remote access tools with built-in features may interact directly with the Windows API to gather information. The Registry may also be modified through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001), which may require additional logging features to be configured in the operating system to collect necessary information for analysis.

Monitor for processes, command-line arguments, and API calls associated with concealing Registry keys, such as Reghide. (Citation: Microsoft Reghide NOV 2006) Inspect and cleanup malicious hidden Registry entries using Native Windows API calls and/or tools such as Autoruns (Citation: SpectorOps Hiding Reg Jul 2017) and RegDelNull (Citation: Microsoft RegDelNull July 2016).

### Defenses Bypassed

Host forensic analysis

### Data Sources

  - Command: Command Execution
  -  Network Traffic: Network Traffic Flow
  -  Process: OS API Execution
  -  Process: Process Creation
  -  Windows Registry: Windows Registry Key Creation
  -  Windows Registry: Windows Registry Key Deletion
  -  Windows Registry: Windows Registry Key Modification
### Detection Rule

```query
tag: detection_rule
tag: T1112
```

### Rule Testing

```query
tag: atomic_test
tag: T1112
```
