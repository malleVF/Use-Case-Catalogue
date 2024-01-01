---
title: "Potential Rcdll.DLL Sideloading"
status: "experimental"
created: "2023/03/13"
last_modified: "2023/03/15"
tags: [defense_evasion, privilege_escalation, t1574_001, t1574_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Potential Rcdll.DLL Sideloading

### Description

Detects potential DLL sideloading of rcdll.dll

```yml
title: Potential Rcdll.DLL Sideloading
id: 6e78b74f-c762-4800-82ad-f66787f10c8a
status: experimental
description: Detects potential DLL sideloading of rcdll.dll
references:
    - https://www.trendmicro.com/en_us/research/23/c/iron-tiger-sysupdate-adds-linux-targeting.html
author: X__Junior (Nextron Systems)
date: 2023/03/13
modified: 2023/03/15
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1574.001
    - attack.t1574.002
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\rcdll.dll'
    filter:
        ImageLoaded|startswith:
            - 'C:\Program Files (x86)\Microsoft Visual Studio\'
            - 'C:\Program Files (x86)\Windows Kits\'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high

```
