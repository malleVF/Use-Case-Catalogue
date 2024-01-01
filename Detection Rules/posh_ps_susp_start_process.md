---
title: "Suspicious Start-Process PassThru"
status: "test"
created: "2022/01/15"
last_modified: ""
tags: [defense_evasion, t1036_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Suspicious Start-Process PassThru

### Description

Powershell use PassThru option to start in background

```yml
title: Suspicious Start-Process PassThru
id: 0718cd72-f316-4aa2-988f-838ea8533277
status: test
description: Powershell use PassThru option to start in background
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1036.003/T1036.003.md
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/Start-Process?view=powershell-5.1&viewFallbackFrom=powershell-7
author: frack113
date: 2022/01/15
tags:
    - attack.defense_evasion
    - attack.t1036.003
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains|all:
            - Start-Process
            - '-PassThru '
            - '-FilePath '
    condition: selection
falsepositives:
    - Legitimate PowerShell scripts
level: medium

```
