---
title: "Potential RjvPlatform.DLL Sideloading From Non-Default Location"
status: "experimental"
created: "2023/06/09"
last_modified: ""
tags: [defense_evasion, privilege_escalation, t1574_001, t1574_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Potential RjvPlatform.DLL Sideloading From Non-Default Location

### Description

Detects potential DLL sideloading of "RjvPlatform.dll" by "SystemResetPlatform.exe" located in a non-default location.

```yml
title: Potential RjvPlatform.DLL Sideloading From Non-Default Location
id: 0e0bc253-07ed-43f1-816d-e1b220fe8971
status: experimental
description: Detects potential DLL sideloading of "RjvPlatform.dll" by "SystemResetPlatform.exe" located in a non-default location.
references:
    - https://twitter.com/0gtweet/status/1666716511988330499
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
        ImageLoaded|endswith: '\RjvPlatform.dll'
        Image: '\SystemResetPlatform.exe'
    filter_main_legit_path:
        Image|startswith: 'C:\Windows\System32\SystemResetPlatform\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unlikely
level: high

```
