---
title: "Taskmgr as Parent"
status: "test"
created: "2018/03/13"
last_modified: "2021/11/27"
tags: [defense_evasion, t1036, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "low"
---

## Taskmgr as Parent

### Description

Detects the creation of a process from Windows task manager

```yml
title: Taskmgr as Parent
id: 3d7679bd-0c00-440c-97b0-3f204273e6c7
status: test
description: Detects the creation of a process from Windows task manager
author: Florian Roth (Nextron Systems)
date: 2018/03/13
modified: 2021/11/27
tags:
    - attack.defense_evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\taskmgr.exe'
    filter:
        Image|endswith:
            - '\resmon.exe'
            - '\mmc.exe'
            - '\taskmgr.exe'
    condition: selection and not filter
fields:
    - Image
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Administrative activity
level: low

```
