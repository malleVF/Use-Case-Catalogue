---
title: "Sticky Key Like Backdoor Usage - Registry"
status: "test"
created: "2018/03/15"
last_modified: "2022/11/26"
tags: [privilege_escalation, persistence, t1546_008, car_2014-11-003, car_2014-11-008, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "critical"
---

## Sticky Key Like Backdoor Usage - Registry

### Description

Detects the usage and installation of a backdoor that uses an option to register a malicious debugger for built-in tools that are accessible in the login screen

```yml
title: Sticky Key Like Backdoor Usage - Registry
id: baca5663-583c-45f9-b5dc-ea96a22ce542
status: test
description: Detects the usage and installation of a backdoor that uses an option to register a malicious debugger for built-in tools that are accessible in the login screen
references:
    - https://blogs.technet.microsoft.com/jonathantrull/2016/10/03/detecting-sticky-key-backdoors/
    - https://bazaar.abuse.ch/sample/6f3aa9362d72e806490a8abce245331030d1ab5ac77e400dd475748236a6cc81/
author: Florian Roth (Nextron Systems), @twjackomo, Jonhnathan Ribeiro, oscd.community
date: 2018/03/15
modified: 2022/11/26
tags:
    - attack.privilege_escalation
    - attack.persistence
    - attack.t1546.008
    - car.2014-11-003
    - car.2014-11-008
logsource:
    category: registry_event
    product: windows
detection:
    selection_registry:
        TargetObject|endswith:
            - '\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\Debugger'
            - '\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe\Debugger'
            - '\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe\Debugger'
            - '\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Magnify.exe\Debugger'
            - '\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Narrator.exe\Debugger'
            - '\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DisplaySwitch.exe\Debugger'
            - '\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\atbroker.exe\Debugger'
            - '\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\HelpPane.exe\Debugger'
    condition: selection_registry
falsepositives:
    - Unlikely
level: critical

```
