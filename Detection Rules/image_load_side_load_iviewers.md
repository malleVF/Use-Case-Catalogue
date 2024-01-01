---
title: "Potential Iviewers.DLL Sideloading"
status: "experimental"
created: "2023/03/21"
last_modified: ""
tags: [defense_evasion, privilege_escalation, t1574_001, t1574_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Potential Iviewers.DLL Sideloading

### Description

Detects potential DLL sideloading of "iviewers.dll" (OLE/COM Object Interface Viewer)

```yml
title: Potential Iviewers.DLL Sideloading
id: 4c21b805-4dd7-469f-b47d-7383a8fcb437
status: experimental
description: Detects potential DLL sideloading of "iviewers.dll" (OLE/COM Object Interface Viewer)
references:
    - https://www.secureworks.com/research/shadowpad-malware-analysis
author: X__Junior (Nextron Systems)
date: 2023/03/21
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
        ImageLoaded|endswith: '\iviewers.dll'
    filter:
        ImageLoaded|startswith:
            - 'C:\Program Files (x86)\Windows Kits\'
            - 'C:\Program Files\Windows Kits\'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high

```
