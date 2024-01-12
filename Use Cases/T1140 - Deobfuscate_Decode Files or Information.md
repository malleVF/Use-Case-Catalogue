---
created: 2017-12-14
last_modified: 2023-08-14
version: 1.3
tactics: Defense Evasion
url: https://attack.mitre.org/techniques/T1140
platforms: Linux, Windows, macOS
tags: [T1140, techniques, Defense_Evasion]
---

## Deobfuscate_Decode Files or Information

### Description

Adversaries may use [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027) to hide artifacts of an intrusion from analysis. They may require separate mechanisms to decode or deobfuscate that information depending on how they intend to use it. Methods for doing that include built-in functionality of malware or by using utilities present on the system.

One such example is the use of [certutil](https://attack.mitre.org/software/S0160) to decode a remote access tool portable executable file that has been hidden inside a certificate file.(Citation: Malwarebytes Targeted Attack against Saudi Arabia) Another example is using the Windows <code>copy /b</code> command to reassemble binary fragments into a malicious payload.(Citation: Carbon Black Obfuscation Sept 2016)

Sometimes a user's action may be required to open it for deobfuscation or decryption as part of [User Execution](https://attack.mitre.org/techniques/T1204). The user may also be required to input a password to open a password protected compressed/encrypted file that was provided by the adversary. (Citation: Volexity PowerDuke November 2016)

### Detection

Detecting the action of deobfuscating or decoding files or information may be difficult depending on the implementation. If the functionality is contained within malware and uses the Windows API, then attempting to detect malicious behavior before or after the action may yield better results than attempting to perform analysis on loaded libraries or API calls. If scripts are used, then collecting the scripts for analysis may be necessary. Perform process and command-line monitoring to detect potentially malicious behavior related to scripts and system utilities such as [certutil](https://attack.mitre.org/software/S0160).

Monitor the execution file paths and command-line arguments for common archive file applications and extensions, such as those for Zip and RAR archive tools, and correlate with other suspicious behavior to reduce false positives from normal user and administrator behavior.

### Defenses Bypassed

Anti-virus, Host Intrusion Prevention Systems, Network Intrusion Detection System, Signature-based Detection

### Data Sources

  - File: File Modification
  -  Process: Process Creation
  -  Script: Script Execution
### Detection Rule

```query
tag: detection_rule
tag: T1140
```

### Rule Testing

```query
tag: atomic_test
tag: T1140
```
