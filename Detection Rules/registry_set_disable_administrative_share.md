---
title: "Disable Administrative Share Creation at Startup"
status: "test"
created: "2022/01/16"
last_modified: "2023/08/17"
tags: [defense_evasion, t1070_005, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Disable Administrative Share Creation at Startup

### Description

Administrative shares are hidden network shares created by Microsoft Windows NT operating systems that grant system administrators remote access to every disk volume on a network-connected system

```yml
title: Disable Administrative Share Creation at Startup
id: c7dcacd0-cc59-4004-b0a4-1d6cdebe6f3e
status: test
description: Administrative shares are hidden network shares created by Microsoft Windows NT operating systems that grant system administrators remote access to every disk volume on a network-connected system
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070.005/T1070.005.md#atomic-test-4---disable-administrative-share-creation-at-startup
author: frack113
date: 2022/01/16
modified: 2023/08/17
tags:
    - attack.defense_evasion
    - attack.t1070.005
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|startswith: 'HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\'
        TargetObject|endswith:
            - 'AutoShareWks'
            - 'AutoShareServer'
        Details: 'DWORD (0x00000000)'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
