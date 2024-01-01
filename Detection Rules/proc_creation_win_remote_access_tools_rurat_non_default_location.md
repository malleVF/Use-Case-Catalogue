---
title: "Remote Access Tool - RURAT Execution From Unusual Location"
status: "experimental"
created: "2022/09/19"
last_modified: "2023/03/05"
tags: [defense_evasion, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Remote Access Tool - RURAT Execution From Unusual Location

### Description

Detects execution of Remote Utilities RAT (RURAT) from an unusual location (outside of 'C:\Program Files')

```yml
title: Remote Access Tool - RURAT Execution From Unusual Location
id: e01fa958-6893-41d4-ae03-182477c5e77d
status: experimental
description: Detects execution of Remote Utilities RAT (RURAT) from an unusual location (outside of 'C:\Program Files')
references:
    - https://redcanary.com/blog/misbehaving-rats/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/09/19
modified: 2023/03/05
tags:
    - attack.defense_evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith:
              - '\rutserv.exe'
              - '\rfusclient.exe'
        - Product: 'Remote Utilities'
    filter:
        Image|startswith:
            - 'C:\Program Files\Remote Utilities'
            - 'C:\Program Files (x86)\Remote Utilities'
    condition: selection and not filter
falsepositives:
    - Unknown
level: medium

```