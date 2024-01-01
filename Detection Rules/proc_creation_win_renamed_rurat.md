---
title: "Renamed Remote Utilities RAT (RURAT) Execution"
status: "test"
created: "2022/09/19"
last_modified: "2023/02/03"
tags: [defense_evasion, collection, command_and_control, discovery, s0592, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Renamed Remote Utilities RAT (RURAT) Execution

### Description

Detects execution of renamed Remote Utilities (RURAT) via Product PE header field

```yml
title: Renamed Remote Utilities RAT (RURAT) Execution
id: 9ef27c24-4903-4192-881a-3adde7ff92a5
status: test
description: Detects execution of renamed Remote Utilities (RURAT) via Product PE header field
references:
    - https://redcanary.com/blog/misbehaving-rats/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/09/19
modified: 2023/02/03
tags:
    - attack.defense_evasion
    - attack.collection
    - attack.command_and_control
    - attack.discovery
    - attack.s0592
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Product: 'Remote Utilities'
    filter:
        Image|endswith:
            - '\rutserv.exe'
            - '\rfusclient.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: medium

```