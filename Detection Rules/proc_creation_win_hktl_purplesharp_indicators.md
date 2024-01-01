---
title: "HackTool - PurpleSharp Execution"
status: "test"
created: "2021/06/18"
last_modified: "2023/02/05"
tags: [t1587, resource_development, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "critical"
---

## HackTool - PurpleSharp Execution

### Description

Detects the execution of the PurpleSharp adversary simulation tool

```yml
title: HackTool - PurpleSharp Execution
id: ff23ffbc-3378-435e-992f-0624dcf93ab4
status: test
description: Detects the execution of the PurpleSharp adversary simulation tool
references:
    - https://github.com/mvelazc0/PurpleSharp
author: Florian Roth (Nextron Systems)
date: 2021/06/18
modified: 2023/02/05
tags:
    - attack.t1587
    - attack.resource_development
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|contains: '\purplesharp'
        - OriginalFileName: 'PurpleSharp.exe'
    selection_cli:
        CommandLine|contains:
            - 'xyz123456.exe'
            - 'PurpleSharp'
    condition: 1 of selection_*
falsepositives:
    - Unlikely
level: critical

```
