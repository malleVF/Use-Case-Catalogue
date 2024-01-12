---
created: 2020-02-11
last_modified: 2023-10-03
version: 1.1
tactics: Persistence
url: https://attack.mitre.org/techniques/T1554
platforms: Linux, Windows, macOS
tags: [T1554, techniques, Persistence]
---

## Compromise Client Software Binary

### Description

Adversaries may modify client software binaries to establish persistent access to systems. Client software enables users to access services provided by a server. Common client software types are SSH clients, FTP clients, email clients, and web browsers.

Adversaries may make modifications to client software binaries to carry out malicious tasks when those applications are in use. For example, an adversary may copy source code for the client software, add a backdoor, compile for the target, and replace the legitimate application binary (or support files) with the backdoored one. An adversary may also modify an existing binary by patching in malicious functionality (e.g., IAT Hooking/Entry point patching)(Citation: Unit42 Banking Trojans Hooking 2022) prior to the binary?s legitimate execution. For example, an adversary may modify the entry point of a binary to point to malicious code patched in by the adversary before resuming normal execution flow.(Citation: ESET FontOnLake Analysis 2021)

Since these applications may be routinely executed by the user, the adversary can leverage this for persistent access to the host.

### Detection

Collect and analyze signing certificate metadata and check signature validity on software that executes within the environment. Look for changes to client software that do not correlate with known software or patch cycles. 

Consider monitoring for anomalous behavior from client applications, such as atypical module loads, file reads/writes, or network connections.

### Defenses Bypassed



### Data Sources

  - File: File Creation
  -  File: File Deletion
  -  File: File Metadata
  -  File: File Modification
### Detection Rule

```query
tag: detection_rule
tag: T1554
```

### Rule Testing

```query
tag: atomic_test
tag: T1554
```
