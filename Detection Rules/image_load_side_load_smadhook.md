---
title: "Potential SmadHook.DLL Sideloading"
status: "experimental"
created: "2023/06/01"
last_modified: ""
tags: [defense_evasion, privilege_escalation, t1574_001, t1574_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Potential SmadHook.DLL Sideloading

### Description

Detects potential DLL sideloading of "SmadHook.dll", a DLL used by SmadAV antivirus

```yml
title: Potential SmadHook.DLL Sideloading
id: 24b6cf51-6122-469e-861a-22974e9c1e5b
status: experimental
description: Detects potential DLL sideloading of "SmadHook.dll", a DLL used by SmadAV antivirus
references:
    - https://research.checkpoint.com/2023/malware-spotlight-camaro-dragons-tinynote-backdoor/
    - https://www.qurium.org/alerts/targeted-malware-against-crph/
author: X__Junior (Nextron Systems)
date: 2023/06/01
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
        ImageLoaded|endswith:
            - '\SmadHook32c.dll'
            - '\SmadHook64c.dll'
    filter_main_legit_path:
        Image:
            - 'C:\Program Files (x86)\SMADAV\SmadavProtect32.exe'
            - 'C:\Program Files (x86)\SMADAV\SmadavProtect64.exe'
            - 'C:\Program Files\SMADAV\SmadavProtect32.exe'
            - 'C:\Program Files\SMADAV\SmadavProtect64.exe'
        ImageLoaded|startswith:
            - 'C:\Program Files (x86)\SMADAV\'
            - 'C:\Program Files\SMADAV\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unlikely
level: high

```
