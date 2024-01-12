---
created: 2019-04-17
last_modified: 2023-10-02
version: 1.4
tactics: Impact
url: https://attack.mitre.org/techniques/T1496
platforms: Containers, IaaS, Linux, Windows, macOS
tags: [T1496, techniques, Impact]
---

## Resource Hijacking

### Description

Adversaries may leverage the resources of co-opted systems to complete resource-intensive tasks, which may impact system and/or hosted service availability. 

One common purpose for Resource Hijacking is to validate transactions of cryptocurrency networks and earn virtual currency. Adversaries may consume enough system resources to negatively impact and/or cause affected machines to become unresponsive.(Citation: Kaspersky Lazarus Under The Hood Blog 2017) Servers and cloud-based systems are common targets because of the high potential for available resources, but user endpoint systems may also be compromised and used for Resource Hijacking and cryptocurrency mining.(Citation: CloudSploit - Unused AWS Regions) Containerized environments may also be targeted due to the ease of deployment via exposed APIs and the potential for scaling mining activities by deploying or compromising multiple containers within an environment or cluster.(Citation: Unit 42 Hildegard Malware)(Citation: Trend Micro Exposed Docker APIs)

Additionally, some cryptocurrency mining malware identify then kill off processes for competing malware to ensure it?s not competing for resources.(Citation: Trend Micro War of Crypto Miners)

Adversaries may also use malware that leverages a system's network bandwidth as part of a botnet in order to facilitate [Network Denial of Service](https://attack.mitre.org/techniques/T1498) campaigns and/or to seed malicious torrents.(Citation: GoBotKR) Alternatively, they may engage in proxyjacking by selling use of the victims' network bandwidth and IP address to proxyware services.(Citation: Sysdig Proxyjacking)

### Detection

Consider monitoring process resource usage to determine anomalous activity associated with malicious hijacking of computer resources such as CPU, memory, and graphics processing resources. Monitor for suspicious use of network resources associated with cryptocurrency mining software. Monitor for common cryptomining software process names and files on local systems that may indicate compromise and resource usage.

### Defenses Bypassed



### Data Sources

  - Command: Command Execution
  -  File: File Creation
  -  Network Traffic: Network Connection Creation
  -  Network Traffic: Network Traffic Flow
  -  Process: Process Creation
  -  Sensor Health: Host Status
### Detection Rule

```query
tag: detection_rule
tag: T1496
```

### Rule Testing

```query
tag: atomic_test
tag: T1496
```
