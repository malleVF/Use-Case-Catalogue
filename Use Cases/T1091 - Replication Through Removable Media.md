---
created: 2017-05-31
last_modified: 2023-10-17
version: 1.2
tactics: Initial Access, Lateral Movement
url: https://attack.mitre.org/techniques/T1091
platforms: Windows
tags: [T1091, techniques, Initial_Access,_Lateral_Movement]
---

## Replication Through Removable Media

### Description

Adversaries may move onto systems, possibly those on disconnected or air-gapped networks, by copying malware to removable media and taking advantage of Autorun features when the media is inserted into a system and executes. In the case of Lateral Movement, this may occur through modification of executable files stored on removable media or by copying malware and renaming it to look like a legitimate file to trick users into executing it on a separate system. In the case of Initial Access, this may occur through manual manipulation of the media, modification of systems used to initially format the media, or modification to the media's firmware itself.

Mobile devices may also be used to infect PCs with malware if connected via USB.(Citation: Exploiting Smartphone USB ) This infection may be achieved using devices (Android, iOS, etc.) and, in some instances, USB charging cables.(Citation: Windows Malware Infecting Android)(Citation: iPhone Charging Cable Hack) For example, when a smartphone is connected to a system, it may appear to be mounted similar to a USB-connected disk drive. If malware that is compatible with the connected system is on the mobile device, the malware could infect the machine (especially if Autorun features are enabled).

### Detection

Monitor file access on removable media. Detect processes that execute from removable media after it is mounted or when initiated by a user. If a remote access tool is used in this manner to move laterally, then additional actions are likely to occur after execution, such as opening network connections for Command and Control and system and network information Discovery.

### Defenses Bypassed



### Data Sources

  - Drive: Drive Creation
  -  File: File Access
  -  File: File Creation
  -  Process: Process Creation
### Detection Rule

```query
tag: detection_rule
tag: T1091
```

### Rule Testing

```query
tag: atomic_test
tag: T1091
```
