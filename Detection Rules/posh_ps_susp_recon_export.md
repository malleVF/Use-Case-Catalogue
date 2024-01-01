---
title: "Recon Information for Export with PowerShell"
status: "test"
created: "2021/07/30"
last_modified: "2022/12/25"
tags: [collection, t1119, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Recon Information for Export with PowerShell

### Description

Once established within a system or network, an adversary may use automated techniques for collecting internal data

```yml
title: Recon Information for Export with PowerShell
id: a9723fcc-881c-424c-8709-fd61442ab3c3
status: test
description: Once established within a system or network, an adversary may use automated techniques for collecting internal data
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1119/T1119.md
author: frack113
date: 2021/07/30
modified: 2022/12/25
tags:
    - attack.collection
    - attack.t1119
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection_action:
        ScriptBlockText|contains:
            - 'Get-Service '
            - 'Get-ChildItem '
            - 'Get-Process '
    selection_redirect:
        ScriptBlockText|contains: '> $env:TEMP\'
    condition: all of selection*
falsepositives:
    - Unknown
level: medium

```
