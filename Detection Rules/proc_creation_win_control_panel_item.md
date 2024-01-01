---
title: "Control Panel Items"
status: "test"
created: "2020/06/22"
last_modified: "2023/10/11"
tags: [execution, defense_evasion, t1218_002, persistence, t1546, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Control Panel Items

### Description

Detects the malicious use of a control panel item

```yml
title: Control Panel Items
id: 0ba863e6-def5-4e50-9cea-4dd8c7dc46a4
status: test
description: Detects the malicious use of a control panel item
references:
    - https://ired.team/offensive-security/code-execution/code-execution-through-control-panel-add-ins
author: Kyaw Min Thein, Furkan Caliskan (@caliskanfurkan_)
date: 2020/06/22
modified: 2023/10/11
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1218.002
    - attack.persistence
    - attack.t1546
logsource:
    product: windows
    category: process_creation
detection:
    selection_reg_img:
        - Image|endswith: '\reg.exe'
        - OriginalFileName: 'reg.exe'
    selection_reg_cli:
        CommandLine|contains|all:
            - 'add'
            - 'CurrentVersion\Control Panel\CPLs'
    selection_cpl:
        CommandLine|endswith: '.cpl'
    filter_cpl_sys:
        CommandLine|contains:
            - '\System32\'
            - '%System%'
            - '|C:\Windows\system32|'
    filter_cpl_igfx:
        CommandLine|contains|all:
            - 'regsvr32 '
            - ' /s '
            - 'igfxCPL.cpl'
    condition: all of selection_reg_* or (selection_cpl and not 1 of filter_cpl_*)
falsepositives:
    - Unknown
level: high

```
