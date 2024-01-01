---
title: "Potential Suspicious Winget Package Installation"
status: "experimental"
created: "2023/04/18"
last_modified: ""
tags: [defense_evasion, persistence, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Potential Suspicious Winget Package Installation

### Description

Detects potential suspicious winget package installation from a suspicious source.

```yml
title: Potential Suspicious Winget Package Installation
id: a3f5c081-e75b-43a0-9f5b-51f26fe5dba2
status: experimental
description: Detects potential suspicious winget package installation from a suspicious source.
references:
    - https://github.com/nasbench/Misc-Research/tree/b9596e8109dcdb16ec353f316678927e507a5b8d/LOLBINs/Winget
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/04/18
tags:
    - attack.defense_evasion
    - attack.persistence
logsource:
    product: windows
    category: create_stream_hash
detection:
    selection:
        Contents|startswith: '[ZoneTransfer]  ZoneId=3'
        Contents|contains:
            # Note: Add any untrusted sources that are custom to your env
            - '://1'
            - '://2'
            - '://3'
            - '://4'
            - '://5'
            - '://6'
            - '://7'
            - '://8'
            - '://9'
        TargetFilename|endswith: ':Zone.Identifier'
        TargetFilename|contains: '\AppData\Local\Temp\WinGet\'
    condition: selection
falsepositives:
    - Unknown
level: high

```