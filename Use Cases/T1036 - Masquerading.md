---
created: 2017-05-31
last_modified: 2023-10-15
version: 1.6
tactics: Defense Evasion
url: https://attack.mitre.org/techniques/T1036
platforms: Containers, Linux, Windows, macOS
tags: [T1036, techniques, Defense_Evasion]
---

## Masquerading

### Description

Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools. Masquerading occurs when the name or location of an object, legitimate or malicious, is manipulated or abused for the sake of evading defenses and observation. This may include manipulating file metadata, tricking users into misidentifying the file type, and giving legitimate task or service names.

Renaming abusable system utilities to evade security monitoring is also a form of [Masquerading](https://attack.mitre.org/techniques/T1036).(Citation: LOLBAS Main Site) Masquerading may also include the use of [Proxy](https://attack.mitre.org/techniques/T1090) or VPNs to disguise IP addresses, which can allow adversaries to blend in with normal network traffic and bypass conditional access policies or anti-abuse protections.

### Detection

Collect file hashes; file names that do not match their expected hash are suspect. Perform file monitoring; files with known names but in unusual locations are suspect. Likewise, files that are modified outside of an update or patch are suspect.

If file names are mismatched between the file name on disk and that of the binary's PE metadata, this is a likely indicator that a binary was renamed after it was compiled. Collecting and comparing disk and resource filenames for binaries by looking to see if the InternalName, OriginalFilename, and/or ProductName match what is expected could provide useful leads, but may not always be indicative of malicious activity. (Citation: Elastic Masquerade Ball) Do not focus on the possible names a file could have, but instead on the command-line arguments that are known to be used and are distinct because it will have a better rate of detection.(Citation: Twitter ItsReallyNick Masquerading Update)

Look for indications of common characters that may indicate an attempt to trick users into misidentifying the file type, such as a space as the last character of a file name or the right-to-left override characters"\u202E", "[U+202E]", and "%E2%80%AE?.

### Defenses Bypassed

Application Control

### Data Sources

  - Command: Command Execution
  -  File: File Metadata
  -  File: File Modification
  -  Image: Image Metadata
  -  Process: OS API Execution
  -  Process: Process Creation
  -  Process: Process Metadata
  -  Scheduled Job: Scheduled Job Metadata
  -  Scheduled Job: Scheduled Job Modification
  -  Service: Service Creation
  -  Service: Service Metadata
### Detection Rule

```query
tag: detection_rule
tag: T1036
```

### Rule Testing

```query
tag: atomic_test
tag: T1036
```
