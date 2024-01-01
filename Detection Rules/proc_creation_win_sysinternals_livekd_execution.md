---
title: "Potential Memory Dumping Activity Via LiveKD"
status: "experimental"
created: "2023/05/15"
last_modified: ""
tags: [defense_evasion, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Potential Memory Dumping Activity Via LiveKD

### Description

Detects execution of LiveKD based on PE metadata or image name

```yml
title: Potential Memory Dumping Activity Via LiveKD
id: a85f7765-698a-4088-afa0-ecfbf8d01fa4
status: experimental
description: Detects execution of LiveKD based on PE metadata or image name
references:
    - https://learn.microsoft.com/en-us/sysinternals/downloads/livekd
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/05/15
tags:
    - attack.defense_evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith:
              - '\livekd.exe'
              - '\livekd64.exe'
        - OriginalFileName: 'livekd.exe'
    condition: selection
falsepositives:
    - Administration and debugging activity (must be investigated)
level: medium

```
