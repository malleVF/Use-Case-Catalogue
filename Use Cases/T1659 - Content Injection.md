---
created: 2023-09-01
last_modified: 2023-10-01
version: 1.0
tactics: Command and Control, Initial Access
url: https://attack.mitre.org/techniques/T1659
platforms: Linux, Windows, macOS
tags: [T1659, techniques, Command_and_Control,_Initial_Access]
---

## Content Injection

### Description

Adversaries may gain access and continuously communicate with victims by injecting malicious content into systems through online network traffic. Rather than luring victims to malicious payloads hosted on a compromised website (i.e., [Drive-by Target](https://attack.mitre.org/techniques/T1608/004) followed by [Drive-by Compromise](https://attack.mitre.org/techniques/T1189)), adversaries may initially access victims through compromised data-transfer channels where they can manipulate traffic and/or inject their own content. These compromised online network channels may also be used to deliver additional payloads (i.e., [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)) and other data to already compromised systems.(Citation: ESET MoustachedBouncer)

Adversaries may inject content to victim systems in various ways, including:

* From the middle, where the adversary is in-between legitimate online client-server communications (**Note:** this is similar but distinct from [Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557), which describes AiTM activity solely within an enterprise environment) (Citation: Kaspersky Encyclopedia MiTM)
* From the side, where malicious content is injected and races to the client as a fake response to requests of a legitimate online server (Citation: Kaspersky ManOnTheSide)

Content injection is often the result of compromised upstream communication channels, for example at the level of an internet service provider (ISP) as is the case with "lawful interception."(Citation: Kaspersky ManOnTheSide)(Citation: ESET MoustachedBouncer)(Citation: EFF China GitHub Attack)

### Detection



### Defenses Bypassed



### Data Sources

  - File: File Creation
  -  Network Traffic: Network Traffic Content
  -  Process: Process Creation
### Detection Rule

```query
tag: detection_rule
tag: T1659
```

### Rule Testing

```query
tag: atomic_test
tag: T1659
```
