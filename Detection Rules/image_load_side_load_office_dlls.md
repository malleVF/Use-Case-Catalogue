---
title: "Microsoft Office DLL Sideload"
status: "experimental"
created: "2022/08/17"
last_modified: "2023/03/15"
tags: [defense_evasion, persistence, privilege_escalation, t1574_001, t1574_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Microsoft Office DLL Sideload

### Description

Detects DLL sideloading of DLLs that are part of Microsoft Office from non standard location

```yml
title: Microsoft Office DLL Sideload
id: 829a3bdf-34da-4051-9cf4-8ed221a8ae4f
status: experimental
description: Detects DLL sideloading of DLLs that are part of Microsoft Office from non standard location
references:
    - https://hijacklibs.net/ # For list of DLLs that could be sideloaded (search for dlls mentioned here in there)
author: Nasreddine Bencherchali (Nextron Systems), Wietze Beukema (project and research)
date: 2022/08/17
modified: 2023/03/15
tags:
    - attack.defense_evasion
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1574.001
    - attack.t1574.002
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\outllib.dll'
    filter:
        ImageLoaded|startswith:
            - 'C:\Program Files\Microsoft Office\OFFICE'
            - 'C:\Program Files (x86)\Microsoft Office\OFFICE'
            - 'C:\Program Files\Microsoft Office\Root\OFFICE'
            - 'C:\Program Files (x86)\Microsoft Office\Root\OFFICE'
    condition: selection and not filter
falsepositives:
    - Unlikely
level: high

```