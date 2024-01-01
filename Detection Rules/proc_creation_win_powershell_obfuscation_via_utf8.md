---
title: "Potential PowerShell Obfuscation Via WCHAR"
status: "test"
created: "2020/07/09"
last_modified: "2023/01/05"
tags: [execution, t1059_001, defense_evasion, t1027, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Potential PowerShell Obfuscation Via WCHAR

### Description

Detects suspicious encoded character syntax often used for defense evasion

```yml
title: Potential PowerShell Obfuscation Via WCHAR
id: e312efd0-35a1-407f-8439-b8d434b438a6
status: test
description: Detects suspicious encoded character syntax often used for defense evasion
references:
    - https://twitter.com/0gtweet/status/1281103918693482496
author: Florian Roth (Nextron Systems)
date: 2020/07/09
modified: 2023/01/05
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
    - attack.t1027
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: '(WCHAR)0x'
    condition: selection
falsepositives:
    - Unknown
level: high

```
