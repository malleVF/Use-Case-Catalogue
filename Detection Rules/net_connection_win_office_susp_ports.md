---
title: "Suspicious Office Outbound Connections"
status: "experimental"
created: "2023/07/12"
last_modified: "2023/12/15"
tags: [defense_evasion, command_and_control, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Suspicious Office Outbound Connections

### Description

Detects office suit applications communicating to target systems on uncommon ports

```yml
title: Suspicious Office Outbound Connections
id: 3b5ba899-9842-4bc2-acc2-12308498bf42
status: experimental
description: Detects office suit applications communicating to target systems on uncommon ports
references:
    - https://blogs.blackberry.com/en/2023/07/romcom-targets-ukraine-nato-membership-talks-at-nato-summit
author: X__Junior (Nextron Systems)
date: 2023/07/12
modified: 2023/12/15
tags:
    - attack.defense_evasion
    - attack.command_and_control
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Image|endswith:
            - '\excel.exe'
            - '\outlook.exe'
            - '\powerpnt.exe'
            - '\winword.exe'
            - '\wordpad.exe'
            - '\wordview.exe'
    filter_main_ports:
        DestinationPort:
            - 80
            - 139
            - 443
            - 445
            - 465
            - 587
            - 993
            - 995
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Other ports can be used, apply additional filters accordingly
level: medium

```
