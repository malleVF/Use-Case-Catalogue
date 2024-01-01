---
title: "Potential 7za.DLL Sideloading"
status: "experimental"
created: "2023/06/09"
last_modified: ""
tags: [defense_evasion, persistence, privilege_escalation, t1574_001, t1574_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "low"
---

## Potential 7za.DLL Sideloading

### Description

Detects potential DLL sideloading of "7za.dll"

```yml
title: Potential 7za.DLL Sideloading
id: 4f6edb78-5c21-42ab-a558-fd2a6fc1fd57
status: experimental
description: Detects potential DLL sideloading of "7za.dll"
references:
    - https://www.gov.pl/attachment/ee91f24d-3e67-436d-aa50-7fa56acf789d
author: X__Junior
date: 2023/06/09
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
        ImageLoaded|endswith: '\7za.dll'
    filter_main_legit_path:
        Image|startswith:
            - 'C:\Program Files (x86)\'
            - 'C:\Program Files\'
        ImageLoaded|startswith:
            - 'C:\Program Files (x86)\'
            - 'C:\Program Files\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Legitimate third party application located in "AppData" may leverage this DLL to offer 7z compression functionality and may generate false positives. Apply additional filters as needed.
level: low

```
