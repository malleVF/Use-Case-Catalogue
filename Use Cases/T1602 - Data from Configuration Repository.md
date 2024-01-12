---
created: 2020-10-19
last_modified: 2022-04-19
version: 1.0
tactics: Collection
url: https://attack.mitre.org/techniques/T1602
platforms: Network
tags: [T1602, techniques, Collection]
---

## Data from Configuration Repository

### Description

Adversaries may collect data related to managed devices from configuration repositories. Configuration repositories are used by management systems in order to configure, manage, and control data on remote systems. Configuration repositories may also facilitate remote access and administration of devices.

Adversaries may target these repositories in order to collect large quantities of sensitive system administration data. Data from configuration repositories may be exposed by various protocols and software and can store a wide variety of data, much of which may align with adversary Discovery objectives.(Citation: US-CERT-TA18-106A)(Citation: US-CERT TA17-156A SNMP Abuse 2017)

### Detection

Identify network traffic sent or received by untrusted hosts or networks that solicits and obtains the configuration information of the queried device.(Citation: Cisco Advisory SNMP v3 Authentication Vulnerabilities)

### Defenses Bypassed



### Data Sources

  - Network Traffic: Network Connection Creation
  -  Network Traffic: Network Traffic Content
### Detection Rule

```query
tag: detection_rule
tag: T1602
```

### Rule Testing

```query
tag: atomic_test
tag: T1602
```
