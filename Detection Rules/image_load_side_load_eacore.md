---
title: "Potential EACore.DLL Sideloading"
status: "experimental"
created: "2023/08/03"
last_modified: ""
tags: [defense_evasion, privilege_escalation, t1574_001, t1574_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Potential EACore.DLL Sideloading

### Description

Detects potential DLL sideloading of "EACore.dll"

```yml
title: Potential EACore.DLL Sideloading
id: edd3ddc3-386f-4ba5-9ada-4376b2cfa7b5
status: experimental
description: Detects potential DLL sideloading of "EACore.dll"
references:
    - https://research.checkpoint.com/2023/beyond-the-horizon-traveling-the-world-on-camaro-dragons-usb-flash-drives/
author: X__Junior (Nextron Systems)
date: 2023/08/03
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
        ImageLoaded|endswith: '\EACore.dll'
    filter_main_legit_path:
        Image|contains|all:
            - 'C:\Program Files\Electronic Arts\EA Desktop\'
            - '\EACoreServer.exe'
        ImageLoaded|startswith: 'C:\Program Files\Electronic Arts\EA Desktop\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unlikely
level: high

```
