---
title: "Potential Chrome Frame Helper DLL Sideloading"
status: "experimental"
created: "2022/08/17"
last_modified: "2023/05/15"
tags: [defense_evasion, persistence, privilege_escalation, t1574_001, t1574_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Potential Chrome Frame Helper DLL Sideloading

### Description

Detects potential DLL sideloading of "chrome_frame_helper.dll"

```yml
title: Potential Chrome Frame Helper DLL Sideloading
id: 72ca7c75-bf85-45cd-aca7-255d360e423c
status: experimental
description: Detects potential DLL sideloading of "chrome_frame_helper.dll"
references:
    - https://hijacklibs.net/entries/3rd_party/google/chrome_frame_helper.html
author: Nasreddine Bencherchali (Nextron Systems), Wietze Beukema (project and research)
date: 2022/08/17
modified: 2023/05/15
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
        ImageLoaded|endswith: '\chrome_frame_helper.dll'
    filter_main_path:
        ImageLoaded|startswith:
            - 'C:\Program Files\Google\Chrome\Application\'
            - 'C:\Program Files (x86)\Google\Chrome\Application\'
    filter_optional_user_path:
        ImageLoaded|contains: '\AppData\local\Google\Chrome\Application\'
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Unknown
level: medium

```
