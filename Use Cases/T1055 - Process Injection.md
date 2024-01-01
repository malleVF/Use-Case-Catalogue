---
created: 2017-05-31
last_modified: 2023-03-30
version: 1.3
tactics: Defense Evasion, Privilege Escalation
url: https://attack.mitre.org/techniques/T1055
platforms: Linux, Windows, macOS
tags: [T1055, techniques, Defense_Evasion,Privilege_Escalation]
---

## Process Injection

### Description

Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges. Process injection is a method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process. 

There are many different ways to inject code into a process, many of which abuse legitimate functionalities. These implementations exist for every major OS but are typically platform specific. 

More sophisticated samples may perform multiple process injections to segment modules and further evade detection, utilizing named pipes or other inter-process communication (IPC) mechanisms as a communication channel. 

### Detection

Monitoring Windows API calls indicative of the various types of code injection may generate a significant amount of data and may not be directly useful for defense unless collected under specific circumstances for known bad sequences of calls, since benign use of API functions may be common and difficult to distinguish from malicious behavior. Windows API calls such as <code>CreateRemoteThread</code>, <code>SuspendThread</code>/<code>SetThreadContext</code>/<code>ResumeThread</code>, <code>QueueUserAPC</code>/<code>NtQueueApcThread</code>, and those that can be used to modify memory within another process, such as <code>VirtualAllocEx</code>/<code>WriteProcessMemory</code>, may be used for this technique.(Citation: Elastic Process Injection July 2017) 

Monitor DLL/PE file events, specifically creation of these binary files as well as the loading of DLLs into processes. Look for DLLs that are not recognized or not normally loaded into a process. 

Monitoring for Linux specific calls such as the ptrace system call should not generate large amounts of data due to their specialized nature, and can be a very effective method to detect some of the common process injection methods.(Citation: ArtOfMemoryForensics)  (Citation: GNU Acct)  (Citation: RHEL auditd)  (Citation: Chokepoint preload rootkits) 

Monitor for named pipe creation and connection events (Event IDs 17 and 18) for possible indicators of infected processes with external modules.(Citation: Microsoft Sysmon v6 May 2017) 

Analyze process behavior to determine if a process is performing actions it usually does not, such as opening network connections, reading files, or other suspicious actions that could relate to post-compromise behavior. 

### Defenses Bypassed

Anti-virus, Application control

### Data Sources

  - File: File Metadata
  -  File: File Modification
  -  Module: Module Load
  -  Process: OS API Execution
  -  Process: Process Access
  -  Process: Process Metadata
  -  Process: Process Modification
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1055
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1055
```
