---
created: 2017-05-31
last_modified: 2023-03-30
version: 1.0
tactics: Collection
url: https://attack.mitre.org/techniques/T1123
platforms: Linux, Windows, macOS
tags: [T1123, techniques, Collection]
---

## Audio Capture

### Description

An adversary can leverage a computer's peripheral devices (e.g., microphones and webcams) or applications (e.g., voice and video call services) to capture audio recordings for the purpose of listening into sensitive conversations to gather information.

Malware or scripts may be used to interact with the devices through an available API provided by the operating system or an application to capture audio. Audio files may be written to disk and exfiltrated later.

### Detection

Detection of this technique may be difficult due to the various APIs that may be used. Telemetry data regarding API use may not be useful depending on how a system is normally used, but may provide context to other potentially malicious activity occurring on a system.

Behavior that could indicate technique use include an unknown or unusual process accessing APIs associated with devices or software that interact with the microphone, recording devices, or recording software, and a process periodically writing files to disk that contain audio data.

### Defenses Bypassed



### Data Sources

  - Command: Command Execution
  -  Process: OS API Execution
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1123
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1123
```
