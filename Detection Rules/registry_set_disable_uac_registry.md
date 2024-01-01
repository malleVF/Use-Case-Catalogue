---
title: "Disable UAC Using Registry"
status: "experimental"
created: "2022/01/05"
last_modified: "2023/08/17"
tags: [privilege_escalation, defense_evasion, t1548_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Disable UAC Using Registry

### Description

Detects when an attacker tries to disable User Account Control (UAC) by changing its registry key HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA from 1 to 0

```yml
title: Disable UAC Using Registry
id: 48437c39-9e5f-47fb-af95-3d663c3f2919
status: experimental
description: Detects when an attacker tries to disable User Account Control (UAC) by changing its registry key HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA from 1 to 0
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1548.002/T1548.002.md#atomic-test-8---disable-uac-using-regexe
author: frack113
date: 2022/01/05
modified: 2023/08/17
tags:
    - attack.privilege_escalation
    - attack.defense_evasion
    - attack.t1548.002
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA
        Details: DWORD (0x00000000)
    condition: selection
falsepositives:
    - Unknown
level: medium

```
