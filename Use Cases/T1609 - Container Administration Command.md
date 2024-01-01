---
created: 2021-03-29
last_modified: 2023-04-15
version: 1.2
tactics: Execution
url: https://attack.mitre.org/techniques/T1609
platforms: Containers
tags: [T1609, techniques, Execution]
---

## Container Administration Command

### Description

Adversaries may abuse a container administration service to execute commands within a container. A container administration service such as the Docker daemon, the Kubernetes API server, or the kubelet may allow remote management of containers within an environment.(Citation: Docker Daemon CLI)(Citation: Kubernetes API)(Citation: Kubernetes Kubelet)

In Docker, adversaries may specify an entrypoint during container deployment that executes a script or command, or they may use a command such as <code>docker exec</code> to execute a command within a running container.(Citation: Docker Entrypoint)(Citation: Docker Exec) In Kubernetes, if an adversary has sufficient permissions, they may gain remote execution in a container in the cluster via interaction with the Kubernetes API server, the kubelet, or by running a command such as <code>kubectl exec</code>.(Citation: Kubectl Exec Get Shell)

### Detection

Container administration service activities and executed commands can be captured through logging of process execution with command-line arguments on the container and the underlying host. In Docker, the daemon log provides insight into events at the daemon and container service level. Kubernetes system component logs may also detect activities running in and out of containers in the cluster. 

### Defenses Bypassed



### Data Sources

  - Command: Command Execution
  -  Process: Process Creation
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1609
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1609
```
