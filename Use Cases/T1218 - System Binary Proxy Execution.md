---
created: 2018-04-18
last_modified: 2022-04-18
version: 3.0
tactics: Defense Evasion
url: https://attack.mitre.org/techniques/T1218
platforms: Linux, Windows, macOS
tags: [T1218, techniques, Defense_Evasion]
---

## System Binary Proxy Execution

### Description

Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed, or otherwise trusted, binaries. Binaries used in this technique are often Microsoft-signed files, indicating that they have been either downloaded from Microsoft or are already native in the operating system.(Citation: LOLBAS Project) Binaries signed with trusted digital certificates can typically execute on Windows systems protected by digital signature validation. Several Microsoft signed binaries that are default on Windows installations can be used to proxy execution of other files or commands.

Similarly, on Linux systems adversaries may abuse trusted binaries such as <code>split</code> to proxy execution of malicious commands.(Citation: split man page)(Citation: GTFO split)

### Detection

Monitor processes and command-line parameters for signed binaries that may be used to proxy execution of malicious files. Compare recent invocations of signed binaries that may be used to proxy execution with prior history of known good arguments and loaded files to determine anomalous and potentially adversarial activity. Legitimate programs used in suspicious ways, like msiexec.exe downloading an MSI file from the Internet, may be indicative of an intrusion. Correlate activity with other suspicious behavior to reduce false positives that may be due to normal benign use by users and administrators.

Monitor for file activity (creations, downloads, modifications, etc.), especially for file types that are not typical within an environment and may be indicative of adversary activity.

### Defenses Bypassed

Anti-virus, Application control, Digital Certificate Validation

### Data Sources

  - Command: Command Execution
  -  File: File Creation
  -  Module: Module Load
  -  Network Traffic: Network Connection Creation
  -  Process: OS API Execution
  -  Process: Process Creation
  -  Windows Registry: Windows Registry Key Modification
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1218
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1218
```
