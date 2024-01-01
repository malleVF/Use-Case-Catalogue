---
title: "CreateRemoteThread API and LoadLibrary"
status: "test"
created: "2019/08/11"
last_modified: "2021/11/27"
tags: [defense_evasion, t1055_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## CreateRemoteThread API and LoadLibrary

### Description

Detects potential use of CreateRemoteThread api and LoadLibrary function to inject DLL into a process

```yml
title: CreateRemoteThread API and LoadLibrary
id: 052ec6f6-1adc-41e6-907a-f1c813478bee
status: test
description: Detects potential use of CreateRemoteThread api and LoadLibrary function to inject DLL into a process
references:
    - https://threathunterplaybook.com/hunts/windows/180719-DLLProcessInjectionCreateRemoteThread/notebook.html
author: Roberto Rodriguez @Cyb3rWard0g
date: 2019/08/11
modified: 2021/11/27
tags:
    - attack.defense_evasion
    - attack.t1055.001
logsource:
    product: windows
    category: create_remote_thread
detection:
    selection:
        StartModule|endswith: '\kernel32.dll'
        StartFunction: 'LoadLibraryA'
    condition: selection
falsepositives:
    - Unknown
level: high

```
