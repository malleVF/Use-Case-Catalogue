---
title: "Disable Windows Firewall by Registry"
status: "experimental"
created: "2022/08/19"
last_modified: "2023/08/17"
tags: [defense_evasion, t1562_004, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Disable Windows Firewall by Registry

### Description

Detect set EnableFirewall to 0 to disable the Windows firewall

```yml
title: Disable Windows Firewall by Registry
id: e78c408a-e2ea-43cd-b5ea-51975cf358c0
status: experimental
description: Detect set EnableFirewall to 0 to disable the Windows firewall
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1562.004/T1562.004.md
author: frack113
date: 2022/08/19
modified: 2023/08/17
tags:
    - attack.defense_evasion
    - attack.t1562.004
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith:
            - \SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\EnableFirewall
            - \SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall
        Details: DWORD (0x00000000)
    condition: selection
falsepositives:
    - Unknown
level: medium

```
