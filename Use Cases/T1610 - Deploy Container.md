---
created: 2021-03-29
last_modified: 2023-04-15
version: 1.2
tactics: Defense Evasion, Execution
url: https://attack.mitre.org/techniques/T1610
platforms: Containers
tags: [T1610, techniques, Defense_Evasion,Execution]
---

## Deploy Container

### Description

Adversaries may deploy a container into an environment to facilitate execution or evade defenses. In some cases, adversaries may deploy a new container to execute processes associated with a particular image or deployment, such as processes that execute or download malware. In others, an adversary may deploy a new container configured without network rules, user limitations, etc. to bypass existing defenses within the environment.

Containers can be deployed by various means, such as via Docker's <code>create</code> and <code>start</code> APIs or via a web application such as the Kubernetes dashboard or Kubeflow.(Citation: Docker Containers API)(Citation: Kubernetes Dashboard)(Citation: Kubeflow Pipelines) Adversaries may deploy containers based on retrieved or built malicious images or from benign images that download and execute malicious payloads at runtime.(Citation: Aqua Build Images on Hosts)

### Detection

Monitor for suspicious or unknown container images and pods in your environment. Deploy logging agents on Kubernetes nodes and retrieve logs from sidecar proxies for application pods to detect malicious activity at the cluster level. In Docker, the daemon log provides insight into remote API calls, including those that deploy containers. Logs for management services or applications used to deploy containers other than the native technologies themselves should also be monitored.

### Defenses Bypassed



### Data Sources

  - Application Log: Application Log Content
  -  Container: Container Creation
  -  Container: Container Start
  -  Pod: Pod Creation
  -  Pod: Pod Modification
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1610
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1610
```
