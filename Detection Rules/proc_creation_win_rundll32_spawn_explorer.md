---
title: "RunDLL32 Spawning Explorer"
status: "test"
created: "2022/04/27"
last_modified: "2022/05/25"
tags: [defense_evasion, t1218_011, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## RunDLL32 Spawning Explorer

### Description

Detects RunDLL32.exe spawning explorer.exe as child, which is very uncommon, often observes Gamarue spawning the explorer.exe process in an unusual way

```yml
title: RunDLL32 Spawning Explorer
id: caa06de8-fdef-4c91-826a-7f9e163eef4b
status: test
description: Detects RunDLL32.exe spawning explorer.exe as child, which is very uncommon, often observes Gamarue spawning the explorer.exe process in an unusual way
references:
    - https://redcanary.com/blog/intelligence-insights-november-2021/
author: elhoim, CD_ROM_
date: 2022/04/27
modified: 2022/05/25
tags:
    - attack.defense_evasion
    - attack.t1218.011
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\rundll32.exe'
        Image|endswith: '\explorer.exe'
    filter:
        ParentCommandLine|contains: '\shell32.dll,Control_RunDLL'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high

```