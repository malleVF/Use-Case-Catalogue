---
title: "Sysmon Channel Reference Deletion"
status: "test"
created: "2020/07/14"
last_modified: "2022/10/05"
tags: [defense_evasion, t1112, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## Sysmon Channel Reference Deletion

### Description

Potential threat actor tampering with Sysmon manifest and eventually disabling it

```yml
title: Sysmon Channel Reference Deletion
id: 18beca67-ab3e-4ee3-ba7a-a46ca8d7d0cc
status: test
description: Potential threat actor tampering with Sysmon manifest and eventually disabling it
references:
    - https://twitter.com/Flangvik/status/1283054508084473861
    - https://twitter.com/SecurityJosh/status/1283027365770276866
    - https://securityjosh.github.io/2020/04/23/Mute-Sysmon.html
    - https://gist.github.com/Cyb3rWard0g/cf08c38c61f7e46e8404b38201ca01c8
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
date: 2020/07/14
modified: 2022/10/05
tags:
    - attack.defense_evasion
    - attack.t1112
logsource:
    product: windows
    service: security
detection:
    selection1:
        EventID: 4657
        ObjectName|contains:
            - 'WINEVT\Publishers\{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'
            - 'WINEVT\Channels\Microsoft-Windows-Sysmon/Operational'
        ObjectValueName: 'Enabled'
        NewValue: 0
    selection2:
        EventID: 4663
        ObjectName|contains:
            - 'WINEVT\Publishers\{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'
            - 'WINEVT\Channels\Microsoft-Windows-Sysmon/Operational'
        AccessMask: 0x10000
    condition: 1 of selection*
falsepositives:
    - Unknown
level: high

```