---
title: "Code Executed Via Office Add-in XLL File"
status: "test"
created: "2021/12/28"
last_modified: ""
tags: [persistence, t1137_006, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Code Executed Via Office Add-in XLL File

### Description

Adversaries may abuse Microsoft Office add-ins to obtain persistence on a compromised system.
Office add-ins can be used to add functionality to Office programs


```yml
title: Code Executed Via Office Add-in XLL File
id: 36fbec91-fa1b-4d5d-8df1-8d8edcb632ad
status: test
description: |
    Adversaries may abuse Microsoft Office add-ins to obtain persistence on a compromised system.
    Office add-ins can be used to add functionality to Office programs
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1137.006/T1137.006.md
author: frack113
date: 2021/12/28
tags:
    - attack.persistence
    - attack.t1137.006
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains|all:
            - 'new-object '
            - '-ComObject '
            - '.application'
            - '.RegisterXLL'
    condition: selection
falsepositives:
    - Unknown
level: high

```