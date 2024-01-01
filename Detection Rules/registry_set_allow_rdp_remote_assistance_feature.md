---
title: "Allow RDP Remote Assistance Feature"
status: "experimental"
created: "2022/08/19"
last_modified: "2023/08/17"
tags: [defense_evasion, t1112, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Allow RDP Remote Assistance Feature

### Description

Detect enable rdp feature to allow specific user to rdp connect on the targeted machine

```yml
title: Allow RDP Remote Assistance Feature
id: 37b437cf-3fc5-4c8e-9c94-1d7c9aff842b
status: experimental
description: Detect enable rdp feature to allow specific user to rdp connect on the targeted machine
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1112/T1112.md
author: frack113
date: 2022/08/19
modified: 2023/08/17
tags:
    - attack.defense_evasion
    - attack.t1112
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: 'System\CurrentControlSet\Control\Terminal Server\fAllowToGetHelp'
        Details: DWORD (0x00000001)
    condition: selection
falsepositives:
    - Legitimate use of the feature (alerts should be investigated either way)
level: medium

```