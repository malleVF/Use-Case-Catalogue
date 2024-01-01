---
title: "Gatekeeper Bypass via Xattr"
status: "test"
created: "2020/10/19"
last_modified: "2021/11/27"
tags: [defense_evasion, t1553_001, detection_rule]
logsrc_product: "macos"
logsrc_service: ""
level: "low"
---

## Gatekeeper Bypass via Xattr

### Description

Detects macOS Gatekeeper bypass via xattr utility

```yml
title: Gatekeeper Bypass via Xattr
id: f5141b6d-9f42-41c6-a7bf-2a780678b29b
status: test
description: Detects macOS Gatekeeper bypass via xattr utility
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1553.001/T1553.001.md
author: Daniil Yugoslavskiy, oscd.community
date: 2020/10/19
modified: 2021/11/27
tags:
    - attack.defense_evasion
    - attack.t1553.001
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|endswith: '/xattr'
        CommandLine|contains|all:
            - '-r'
            - 'com.apple.quarantine'
    condition: selection
falsepositives:
    - Legitimate activities
level: low

```
