---
title: "Potential Edputil.DLL Sideloading"
status: "experimental"
created: "2023/06/09"
last_modified: ""
tags: [defense_evasion, privilege_escalation, t1574_001, t1574_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Potential Edputil.DLL Sideloading

### Description

Detects potential DLL sideloading of "edputil.dll"

```yml
title: Potential Edputil.DLL Sideloading
id: e4903324-1a10-4ed3-981b-f6fe3be3a2c2
status: experimental
description: Detects potential DLL sideloading of "edputil.dll"
references:
    - https://alternativeto.net/news/2023/5/cybercriminals-use-wordpad-vulnerability-to-spread-qbot-malware/
author: X__Junior (Nextron Systems)
date: 2023/06/09
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
        ImageLoaded|endswith: '\edputil.dll'
    filter_main_generic:
        ImageLoaded|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
            - 'C\Windows\WinSxS\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unlikely
level: high

```
