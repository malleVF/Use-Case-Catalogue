---
title: "Disable Privacy Settings Experience in Registry"
status: "experimental"
created: "2022/10/02"
last_modified: "2023/08/17"
tags: [defense_evasion, t1562_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Disable Privacy Settings Experience in Registry

### Description

Detects registry modifications that disable Privacy Settings Experience

```yml
title: Disable Privacy Settings Experience in Registry
id: 0372e1f9-0fd2-40f7-be1b-a7b2b848fa7b
status: experimental
description: Detects registry modifications that disable Privacy Settings Experience
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/9e5b12c4912c07562aec7500447b11fa3e17e254/atomics/T1562.001/T1562.001.md
author: frack113
date: 2022/10/02
modified: 2023/08/17
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\SOFTWARE\Policies\Microsoft\Windows\OOBE\DisablePrivacyExperience'
        Details: 'DWORD (0x00000000)'
    condition: selection
falsepositives:
    - Legitimate admin script
level: medium

```