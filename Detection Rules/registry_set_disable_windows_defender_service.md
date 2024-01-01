---
title: "Windows Defender Service Disabled"
status: "experimental"
created: "2022/08/01"
last_modified: "2023/08/17"
tags: [defense_evasion, t1562_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Windows Defender Service Disabled

### Description

Detects when an attacker or tool disables the  Windows Defender service (WinDefend) via the registry

```yml
title: Windows Defender Service Disabled
id: e1aa95de-610a-427d-b9e7-9b46cfafbe6a
status: experimental
description: Detects when an attacker or tool disables the  Windows Defender service (WinDefend) via the registry
references:
    - https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
    - https://gist.github.com/anadr/7465a9fde63d41341136949f14c21105
author: Ján Trenčanský, frack113, AlertIQ, Nasreddine Bencherchali
date: 2022/08/01
modified: 2023/08/17
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    product: windows
    category: registry_set
detection:
    selection:
        TargetObject: 'HKLM\SYSTEM\CurrentControlSet\Services\WinDefend\Start'
        Details: 'DWORD (0x00000004)'
    condition: selection
falsepositives:
    - Administrator actions
level: high

```
