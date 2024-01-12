---
created: 2019-09-04
last_modified: 2022-03-08
version: 2.1
tactics: Persistence
url: https://attack.mitre.org/techniques/T1525
platforms: Containers, IaaS
tags: [T1525, techniques, Persistence]
---

## Implant Internal Image

### Description

Adversaries may implant cloud or container images with malicious code to establish persistence after gaining access to an environment. Amazon Web Services (AWS) Amazon Machine Images (AMIs), Google Cloud Platform (GCP) Images, and Azure Images as well as popular container runtimes such as Docker can be implanted or backdoored. Unlike [Upload Malware](https://attack.mitre.org/techniques/T1608/001), this technique focuses on adversaries implanting an image in a registry within a victim?s environment. Depending on how the infrastructure is provisioned, this could provide persistent access if the infrastructure provisioning tool is instructed to always use the latest image.(Citation: Rhino Labs Cloud Image Backdoor Technique Sept 2019)

A tool has been developed to facilitate planting backdoors in cloud container images.(Citation: Rhino Labs Cloud Backdoor September 2019) If an adversary has access to a compromised AWS instance, and permissions to list the available container images, they may implant a backdoor such as a [Web Shell](https://attack.mitre.org/techniques/T1505/003).(Citation: Rhino Labs Cloud Image Backdoor Technique Sept 2019)

### Detection

Monitor interactions with images and containers by users to identify ones that are added or modified anomalously.

In containerized environments, changes may be detectable by monitoring the Docker daemon logs or setting up and monitoring Kubernetes audit logs depending on registry configuration. 

### Defenses Bypassed



### Data Sources

  - Image: Image Creation
  -  Image: Image Metadata
  -  Image: Image Modification
### Detection Rule

```query
tag: detection_rule
tag: T1525
```

### Rule Testing

```query
tag: atomic_test
tag: T1525
```
