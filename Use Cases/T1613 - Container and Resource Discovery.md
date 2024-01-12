---
created: 2021-03-31
last_modified: 2023-04-15
version: 1.1
tactics: Discovery
url: https://attack.mitre.org/techniques/T1613
platforms: Containers
tags: [T1613, techniques, Discovery]
---

## Container and Resource Discovery

### Description

Adversaries may attempt to discover containers and other resources that are available within a containers environment. Other resources may include images, deployments, pods, nodes, and other information such as the status of a cluster.

These resources can be viewed within web applications such as the Kubernetes dashboard or can be queried via the Docker and Kubernetes APIs.(Citation: Docker API)(Citation: Kubernetes API) In Docker, logs may leak information about the environment, such as the environment?s configuration, which services are available, and what cloud provider the victim may be utilizing. The discovery of these resources may inform an adversary?s next steps in the environment, such as how to perform lateral movement and which methods to utilize for execution. 

### Detection

Establish centralized logging for the activity of container and Kubernetes cluster components. This can be done by deploying logging agents on Kubernetes nodes and retrieving logs from sidecar proxies for application pods to detect malicious activity at the cluster level.

Monitor logs for actions that could be taken to gather information about container infrastructure, including the use of discovery API calls by new or unexpected users. Monitor account activity logs to see actions performed and activity associated with the Kubernetes dashboard and other web applications. 

### Defenses Bypassed



### Data Sources

  - Container: Container Enumeration
  -  Pod: Pod Enumeration
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1613
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "Testing Runbooks" AND #T1613
```
