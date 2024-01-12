---
created: 2021-03-30
last_modified: 2023-04-15
version: 1.4
tactics: Privilege Escalation
url: https://attack.mitre.org/techniques/T1611
platforms: Containers, Linux, Windows
tags: [T1611, techniques, Privilege_Escalation]
---

## Escape to Host

### Description

Adversaries may break out of a container to gain access to the underlying host. This can allow an adversary access to other containerized resources from the host level or to the host itself. In principle, containerized resources should provide a clear separation of application functionality and be isolated from the host environment.(Citation: Docker Overview)

There are multiple ways an adversary may escape to a host environment. Examples include creating a container configured to mount the host?s filesystem using the bind parameter, which allows the adversary to drop payloads and execute control utilities such as cron on the host; utilizing a privileged container to run commands or load a malicious kernel module on the underlying host; or abusing system calls such as `unshare` and `keyctl` to escalate privileges and steal secrets.(Citation: Docker Bind Mounts)(Citation: Trend Micro Privileged Container)(Citation: Intezer Doki July 20)(Citation: Container Escape)(Citation: Crowdstrike Kubernetes Container Escape)(Citation: Keyctl-unmask)

Additionally, an adversary may be able to exploit a compromised container with a mounted container management socket, such as `docker.sock`, to break out of the container via a [Container Administration Command](https://attack.mitre.org/techniques/T1609).(Citation: Container Escape) Adversaries may also escape via [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068), such as exploiting vulnerabilities in global symbolic links in order to access the root directory of a host machine.(Citation: Windows Server Containers Are Open)

Gaining access to the host may provide the adversary with the opportunity to achieve follow-on objectives, such as establishing persistence, moving laterally within the environment, or setting up a command and control channel on the host.

### Detection

Monitor for the deployment of suspicious or unknown container images and pods in your environment, particularly containers running as root. Additionally, monitor for unexpected usage of syscalls such as <code>mount</code> (as well as resulting process activity) that may indicate an attempt to escape from a privileged container to host. In Kubernetes, monitor for cluster-level events associated with changing containers' volume configurations.

### Defenses Bypassed



### Data Sources

  - Container: Container Creation
  -  Kernel: Kernel Module Load
  -  Process: OS API Execution
  -  Process: Process Creation
  -  Volume: Volume Modification
### Detection Rule

```query
tag: detection_rule
tag: T1611
```

### Rule Testing

```query
tag: atomic_test
tag: T1611
```
