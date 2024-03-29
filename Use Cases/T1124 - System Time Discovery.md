---
created: 2017-05-31
last_modified: 2023-04-12
version: 1.3
tactics: Discovery
url: https://attack.mitre.org/techniques/T1124
platforms: Network, Windows
tags: [T1124, techniques, Discovery]
---

## System Time Discovery

### Description

An adversary may gather the system time and/or time zone from a local or remote system. The system time is set and stored by the Windows Time Service within a domain to maintain time synchronization between systems and services in an enterprise network. (Citation: MSDN System Time)(Citation: Technet Windows Time Service)

System time information may be gathered in a number of ways, such as with [Net](https://attack.mitre.org/software/S0039) on Windows by performing <code>net time \\hostname</code> to gather the system time on a remote system. The victim's time zone may also be inferred from the current system time or gathered by using <code>w32tm /tz</code>.(Citation: Technet Windows Time Service)

On network devices, [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) commands such as `show clock detail` can be used to see the current time configuration.(Citation: show_clock_detail_cisco_cmd)

This information could be useful for performing other techniques, such as executing a file with a [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)(Citation: RSA EU12 They're Inside), or to discover locality information based on time zone to assist in victim targeting (i.e. [System Location Discovery](https://attack.mitre.org/techniques/T1614)). Adversaries may also use knowledge of system time as part of a time bomb, or delaying execution until a specified date/time.(Citation: AnyRun TimeBomb)

### Detection

Command-line interface monitoring may be useful to detect instances of net.exe or other command-line utilities being used to gather system time or time zone. Methods of detecting API use for gathering this information are likely less useful due to how often they may be used by legitimate software.

For network infrastructure devices, collect AAA logging to monitor `show` commands being run by non-standard users from non-standard locations.

### Defenses Bypassed



### Data Sources

  - Command: Command Execution
  -  Process: OS API Execution
  -  Process: Process Creation
### Detection Rule

```query
tag: detection_rule
tag: T1124
```

### Rule Testing

```query
tag: atomic_test
tag: T1124
```
