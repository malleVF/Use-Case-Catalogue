---
title: "Powershell Inline Execution From A File"
status: "test"
created: "2022/12/25"
last_modified: ""
tags: [execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Powershell Inline Execution From A File

### Description

Detects inline execution of PowerShell code from a file

```yml
title: Powershell Inline Execution From A File
id: ee218c12-627a-4d27-9e30-d6fb2fe22ed2
status: test
description: Detects inline execution of PowerShell code from a file
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=50
author: frack113
date: 2022/12/25
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: process_creation
detection:
    selection_exec:
        CommandLine|contains:
            - 'iex '
            - 'Invoke-Expression '
            - 'Invoke-Command '
            - 'icm '
    selection_read:
        CommandLine|contains:
            - 'cat '
            - 'get-content '
            - 'type '
    selection_raw:
        CommandLine|contains: ' -raw'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium

```
