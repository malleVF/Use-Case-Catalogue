---
created: 2017-05-31
last_modified: 2023-10-12
version: 2.2
tactics: Execution
url: https://attack.mitre.org/techniques/T1129
platforms: Linux, Windows, macOS
tags: [T1129, techniques, Execution]
---

## Shared Modules

### Description

Adversaries may execute malicious payloads via loading shared modules. Shared modules are executable files that are loaded into processes to provide access to reusable code, such as specific custom functions or invoking OS API functions (i.e., [Native API](https://attack.mitre.org/techniques/T1106)).

Adversaries may use this functionality as a way to execute arbitrary payloads on a victim system. For example, adversaries can modularize functionality of their malware into shared objects that perform various functions such as managing C2 network communications or execution of specific actions on objective.

The Linux & macOS module loader can load and execute shared objects from arbitrary local paths. This functionality resides in `dlfcn.h` in functions such as `dlopen` and `dlsym`. Although macOS can execute `.so` files, common practice uses `.dylib` files.(Citation: Apple Dev Dynamic Libraries)(Citation: Linux Shared Libraries)(Citation: RotaJakiro 2021 netlab360 analysis)(Citation: Unit42 OceanLotus 2017)

The Windows module loader can be instructed to load DLLs from arbitrary local paths and arbitrary Universal Naming Convention (UNC) network paths. This functionality resides in `NTDLL.dll` and is part of the Windows [Native API](https://attack.mitre.org/techniques/T1106) which is called from functions like `LoadLibrary` at run time.(Citation: Microsoft DLL)

### Detection

Monitoring DLL module loads may generate a significant amount of data and may not be directly useful for defense unless collected under specific circumstances, since benign use of Windows modules load functions are common and may be difficult to distinguish from malicious behavior. Legitimate software will likely only need to load routine, bundled DLL modules or Windows system DLLs such that deviation from known module loads may be suspicious. Limiting DLL module loads to `%SystemRoot%` and `%ProgramFiles%` directories will protect against module loads from unsafe paths. 

Correlation of other events with behavior surrounding module loads using API monitoring and suspicious DLLs written to disk will provide additional context to an event that may assist in determining if it is due to malicious behavior.

### Defenses Bypassed



### Data Sources

  - Module: Module Load
  -  Process: OS API Execution
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1129
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1129
```
