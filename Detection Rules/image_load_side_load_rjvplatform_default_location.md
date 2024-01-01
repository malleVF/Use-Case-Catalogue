---
title: "Potential RjvPlatform.DLL Sideloading From Default Location"
status: "experimental"
created: "2023/06/09"
last_modified: ""
tags: [defense_evasion, privilege_escalation, t1574_001, t1574_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Potential RjvPlatform.DLL Sideloading From Default Location

### Description

Detects loading of "RjvPlatform.dll" by the "SystemResetPlatform.exe" binary which can be abused as a method of DLL side loading since the "$SysReset" directory isn't created by default.

```yml
title: Potential RjvPlatform.DLL Sideloading From Default Location
id: 259dda31-b7a3-444f-b7d8-17f96e8a7d0d
status: experimental
description: Detects loading of "RjvPlatform.dll" by the "SystemResetPlatform.exe" binary which can be abused as a method of DLL side loading since the "$SysReset" directory isn't created by default.
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
        Image: 'C:\Windows\System32\SystemResetPlatform\SystemResetPlatform.exe'
        ImageLoaded: 'C:\$SysReset\Framework\Stack\RjvPlatform.dll'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
