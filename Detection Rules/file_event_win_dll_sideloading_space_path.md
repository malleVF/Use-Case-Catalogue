---
title: "DLL Search Order Hijackig Via Additional Space in Path"
status: "test"
created: "2022/07/30"
last_modified: ""
tags: [persistence, privilege_escalation, defense_evasion, t1574_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## DLL Search Order Hijackig Via Additional Space in Path

### Description

Detects when an attacker create a similar folder structure to windows system folders such as (Windows, Program Files...)
but with a space in order to trick DLL load search order and perform a "DLL Search Order Hijacking" attack


```yml
title: DLL Search Order Hijackig Via Additional Space in Path
id: b6f91281-20aa-446a-b986-38a92813a18f
status: test
description: |
    Detects when an attacker create a similar folder structure to windows system folders such as (Windows, Program Files...)
    but with a space in order to trick DLL load search order and perform a "DLL Search Order Hijacking" attack
references:
    - https://twitter.com/cyb3rops/status/1552932770464292864
    - https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows
author: frack113, Nasreddine Bencherchali
date: 2022/07/30
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.defense_evasion
    - attack.t1574.002
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|startswith:
            - 'C:\Windows \'
            - 'C:\Program Files \'
            - 'C:\Program Files (x86) \'
        TargetFilename|endswith: '.dll'
    condition: selection
falsepositives:
    - Unknown
level: high

```
