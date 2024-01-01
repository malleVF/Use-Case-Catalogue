---
title: "Winlogon AllowMultipleTSSessions Enable"
status: "experimental"
created: "2022/09/09"
last_modified: "2023/08/17"
tags: [persistence, defense_evasion, t1112, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Winlogon AllowMultipleTSSessions Enable

### Description

Detects when the 'AllowMultipleTSSessions' value is enabled.
Which allows for multiple Remote Desktop connection sessions to be opened at once.
This is often used by attacker as a way to connect to an RDP session without disconnecting the other users


```yml
title: Winlogon AllowMultipleTSSessions Enable
id: f7997770-92c3-4ec9-b112-774c4ef96f96
status: experimental
description: |
  Detects when the 'AllowMultipleTSSessions' value is enabled.
  Which allows for multiple Remote Desktop connection sessions to be opened at once.
  This is often used by attacker as a way to connect to an RDP session without disconnecting the other users
references:
    - http://blog.talosintelligence.com/2022/09/lazarus-three-rats.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/09/09
modified: 2023/08/17
tags:
    - attack.persistence
    - attack.defense_evasion
    - attack.t1112
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\Microsoft\Windows NT\CurrentVersion\Winlogon\AllowMultipleTSSessions'
        Details|endswith: DWORD (0x00000001)
    condition: selection
falsepositives:
    - Legitimate use of the multi session functionality
level: medium

```
