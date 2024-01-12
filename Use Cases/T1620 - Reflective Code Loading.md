---
created: 2021-10-05
last_modified: 2023-09-29
version: 1.1
tactics: Defense Evasion
url: https://attack.mitre.org/techniques/T1620
platforms: Linux, Windows, macOS
tags: [T1620, techniques, Defense_Evasion]
---

## Reflective Code Loading

### Description

Adversaries may reflectively load code into a process in order to conceal the execution of malicious payloads. Reflective loading involves allocating then executing payloads directly within the memory of the process, vice creating a thread or process backed by a file path on disk. Reflectively loaded payloads may be compiled binaries, anonymous files (only present in RAM), or just snubs of fileless executable code (ex: position-independent shellcode).(Citation: Introducing Donut)(Citation: S1 Custom Shellcode Tool)(Citation: Stuart ELF Memory)(Citation: 00sec Droppers)(Citation: Mandiant BYOL)

Reflective code injection is very similar to [Process Injection](https://attack.mitre.org/techniques/T1055) except that the ?injection? loads code into the processes? own memory instead of that of a separate process. Reflective loading may evade process-based detections since the execution of the arbitrary code may be masked within a legitimate or otherwise benign process. Reflectively loading payloads directly into memory may also avoid creating files or other artifacts on disk, while also enabling malware to keep these payloads encrypted (or otherwise obfuscated) until execution.(Citation: Stuart ELF Memory)(Citation: 00sec Droppers)(Citation: Intezer ACBackdoor)(Citation: S1 Old Rat New Tricks)

### Detection

Monitor for code artifacts associated with reflectively loading code, such as the abuse of .NET functions such as <code>Assembly.Load()</code> and [Native API](https://attack.mitre.org/techniques/T1106) functions such as <code>CreateThread()</code>, <code>memfd_create()</code>, <code>execve()</code>, and/or <code>execveat()</code>.(Citation: 00sec Droppers)(Citation: S1 Old Rat New Tricks)

Monitor for artifacts of abnormal process execution. For example, a common signature related to reflective code loading on Windows is mechanisms related to the .NET Common Language Runtime (CLR) -- such as mscor.dll, mscoree.dll, and clr.dll -- loading into abnormal processes (such as notepad.exe). Similarly, AMSI / ETW traces can be used to identify signs of arbitrary code execution from within the memory of potentially compromised processes.(Citation: MDSec Detecting DOTNET)(Citation: Introducing Donut)

Analyze process behavior to determine if a process is performing actions it usually does not, such as opening network connections, reading files, or other suspicious actions that could relate to post-compromise behavior. 

### Defenses Bypassed

Anti-virus, Application control

### Data Sources

  - Module: Module Load
  -  Process: OS API Execution
  -  Script: Script Execution
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1620
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "Testing Runbooks" AND #T1620
```
