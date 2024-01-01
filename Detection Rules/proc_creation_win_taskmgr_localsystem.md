---
title: "Taskmgr as LOCAL_SYSTEM"
status: "test"
created: "2018/03/18"
last_modified: "2022/05/27"
tags: [defense_evasion, t1036, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Taskmgr as LOCAL_SYSTEM

### Description

Detects the creation of taskmgr.exe process in context of LOCAL_SYSTEM

```yml
title: Taskmgr as LOCAL_SYSTEM
id: 9fff585c-c33e-4a86-b3cd-39312079a65f
status: test
description: Detects the creation of taskmgr.exe process in context of LOCAL_SYSTEM
author: Florian Roth (Nextron Systems)
date: 2018/03/18
modified: 2022/05/27
tags:
    - attack.defense_evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        User|contains: # covers many language settings
            - 'AUTHORI'
            - 'AUTORI'
        Image|endswith: '\taskmgr.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```