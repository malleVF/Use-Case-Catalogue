---
created: 2021-03-30
last_modified: 2023-04-15
version: 1.3
tactics: Defense Evasion
url: https://attack.mitre.org/techniques/T1612
platforms: Containers
tags: [T1612, techniques, Defense_Evasion]
---

## Build Image on Host

### Description

Adversaries may build a container image directly on a host to bypass defenses that monitor for the retrieval of malicious images from a public registry. A remote <code>build</code> request may be sent to the Docker API that includes a Dockerfile that pulls a vanilla base image, such as alpine, from a public or local registry and then builds a custom image upon it.(Citation: Docker Build Image)

An adversary may take advantage of that <code>build</code> API to build a custom image on the host that includes malware downloaded from their C2 server, and then they may utilize [Deploy Container](https://attack.mitre.org/techniques/T1610) using that custom image.(Citation: Aqua Build Images on Hosts)(Citation: Aqua Security Cloud Native Threat Report June 2021) If the base image is pulled from a public registry, defenses will likely not detect the image as malicious since it?s a vanilla image. If the base image already resides in a local registry, the pull may be considered even less suspicious since the image is already in the environment. 

### Detection

Monitor for unexpected Docker image build requests to the Docker daemon on hosts in the environment. Additionally monitor for subsequent network communication with anomalous IPs that have never been seen before in the environment that indicate the download of malicious code.

### Defenses Bypassed



### Data Sources

  - Image: Image Creation
  -  Network Traffic: Network Connection Creation
  -  Network Traffic: Network Traffic Content
  -  Network Traffic: Network Traffic Flow
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1612
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1612
```
