---
title: "Potential MSTSC Shadowing Activity"
status: "test"
created: "2020/01/24"
last_modified: "2023/02/05"
tags: [lateral_movement, t1563_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Potential MSTSC Shadowing Activity

### Description

Detects RDP session hijacking by using MSTSC shadowing

```yml
title: Potential MSTSC Shadowing Activity
id: 6ba5a05f-b095-4f0a-8654-b825f4f16334
status: test
description: Detects RDP session hijacking by using MSTSC shadowing
references:
    - https://twitter.com/kmkz_security/status/1220694202301976576
    - https://github.com/kmkz/Pentesting/blob/47592e5e160d3b86c2024f09ef04ceb87d204995/Post-Exploitation-Cheat-Sheet
author: Florian Roth (Nextron Systems)
date: 2020/01/24
modified: 2023/02/05
tags:
    - attack.lateral_movement
    - attack.t1563.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'noconsentprompt'
            - 'shadow:'
    condition: selection
falsepositives:
    - Unknown
level: high

```
