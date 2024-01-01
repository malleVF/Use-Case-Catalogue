---
title: "PowerShell PSAttack"
status: "test"
created: "2017/03/05"
last_modified: "2022/12/25"
tags: [execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## PowerShell PSAttack

### Description

Detects the use of PSAttack PowerShell hack tool

```yml
title: PowerShell PSAttack
id: b7ec41a4-042c-4f31-a5db-d0fcde9fa5c5
status: test
description: Detects the use of PSAttack PowerShell hack tool
references:
    - https://adsecurity.org/?p=2921
author: Sean Metcalf (source), Florian Roth (Nextron Systems)
date: 2017/03/05
modified: 2022/12/25
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains: 'PS ATTACK!!!'
    condition: selection
falsepositives:
    - Unknown
level: high

```
