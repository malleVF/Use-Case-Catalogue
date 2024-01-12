---
created: 2018-04-18
last_modified: 2022-04-19
version: 1.5
tactics: Execution
url: https://attack.mitre.org/techniques/T1204
platforms: Containers, IaaS, Linux, Windows, macOS
tags: [T1204, techniques, Execution]
---

## User Execution

### Description

An adversary may rely upon specific actions by a user in order to gain execution. Users may be subjected to social engineering to get them to execute malicious code by, for example, opening a malicious document file or link. These user actions will typically be observed as follow-on behavior from forms of [Phishing](https://attack.mitre.org/techniques/T1566).

While [User Execution](https://attack.mitre.org/techniques/T1204) frequently occurs shortly after Initial Access it may occur at other phases of an intrusion, such as when an adversary places a file in a shared directory or on a user's desktop hoping that a user will click on it. This activity may also be seen shortly after [Internal Spearphishing](https://attack.mitre.org/techniques/T1534).

Adversaries may also deceive users into performing actions such as enabling [Remote Access Software](https://attack.mitre.org/techniques/T1219), allowing direct control of the system to the adversary, or downloading and executing malware for [User Execution](https://attack.mitre.org/techniques/T1204). For example, tech support scams can be facilitated through [Phishing](https://attack.mitre.org/techniques/T1566), vishing, or various forms of user interaction. Adversaries can use a combination of these methods, such as spoofing and promoting toll-free numbers or call centers that are used to direct victims to malicious websites, to deliver and execute payloads containing malware or [Remote Access Software](https://attack.mitre.org/techniques/T1219).(Citation: Telephone Attack Delivery)

### Detection

Monitor the execution of and command-line arguments for applications that may be used by an adversary to gain Initial Access that require user interaction. This includes compression applications, such as those for zip files, that can be used to [Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140) in payloads.

Anti-virus can potentially detect malicious documents and files that are downloaded and executed on the user's computer. Endpoint sensing or network sensing can potentially detect malicious events once the file is opened (such as a Microsoft Word document or PDF reaching out to the internet or spawning powershell.exe).

### Defenses Bypassed



### Data Sources

  - Application Log: Application Log Content
  -  Command: Command Execution
  -  Container: Container Creation
  -  Container: Container Start
  -  File: File Creation
  -  Image: Image Creation
  -  Instance: Instance Creation
  -  Instance: Instance Start
  -  Network Traffic: Network Connection Creation
  -  Network Traffic: Network Traffic Content
  -  Process: Process Creation
### Detection Rule

```query
tag: detection_rule
tag: T1204
```

### Rule Testing

```query
tag: atomic_test
tag: T1204
```
