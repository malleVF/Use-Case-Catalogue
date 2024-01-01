---
title: "Disable Windows Security Center Notifications"
status: "experimental"
created: "2022/08/19"
last_modified: "2023/08/17"
tags: [defense_evasion, t1112, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Disable Windows Security Center Notifications

### Description

Detect set UseActionCenterExperience to 0 to disable the Windows security center notification

```yml
title: Disable Windows Security Center Notifications
id: 3ae1a046-f7db-439d-b7ce-b8b366b81fa6
status: experimental
description: Detect set UseActionCenterExperience to 0 to disable the Windows security center notification
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
        TargetObject|endswith: 'Windows\CurrentVersion\ImmersiveShell\UseActionCenterExperience'
        Details: 'DWORD (0x00000000)'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
