---
created: 2021-10-01
last_modified: 2022-04-11
version: 1.0
tactics: Discovery
url: https://attack.mitre.org/techniques/T1619
platforms: IaaS
tags: [T1619, techniques, Discovery]
---

## Cloud Storage Object Discovery

### Description

Adversaries may enumerate objects in cloud storage infrastructure. Adversaries may use this information during automated discovery to shape follow-on behaviors, including requesting all or specific objects from cloud storage.  Similar to [File and Directory Discovery](https://attack.mitre.org/techniques/T1083) on a local host, after identifying available storage services (i.e. [Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580)) adversaries may access the contents/objects stored in cloud infrastructure.

Cloud service providers offer APIs allowing users to enumerate objects stored within cloud storage. Examples include ListObjectsV2 in AWS (Citation: ListObjectsV2) and List Blobs in Azure(Citation: List Blobs) .

### Detection

System and network discovery techniques normally occur throughout an operation as an adversary learns the environment. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as Collection and Exfiltration, based on the information obtained. 
Monitor cloud logs for API calls used for file or object enumeration for unusual activity. 

### Defenses Bypassed



### Data Sources

  - Cloud Storage: Cloud Storage Access
  -  Cloud Storage: Cloud Storage Enumeration
### Detection Rule

```query
tag: detection_rule
tag: T1619
```

### Rule Testing

```query
tag: atomic_test
tag: T1619
```
