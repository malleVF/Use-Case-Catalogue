---
title: "Suspicious IO.FileStream"
status: "test"
created: "2022/01/09"
last_modified: "2022/03/05"
tags: [defense_evasion, t1070_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Suspicious IO.FileStream

### Description

Open a handle on the drive volume via the \\.\ DOS device path specifier and perform direct access read of the first few bytes of the volume.

```yml
title: Suspicious IO.FileStream
id: 70ad982f-67c8-40e0-a955-b920c2fa05cb
status: test
description: Open a handle on the drive volume via the \\.\ DOS device path specifier and perform direct access read of the first few bytes of the volume.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1006/T1006.md
author: frack113
date: 2022/01/09
modified: 2022/03/05
tags:
    - attack.defense_evasion
    - attack.t1070.003
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains|all:
            - New-Object
            - IO.FileStream
            - '\\\\.\\'
    condition: selection
falsepositives:
    - Legitimate PowerShell scripts
level: medium

```