---
title: "Invoke-Obfuscation Via Use MSHTA - PowerShell"
status: "test"
created: "2020/10/08"
last_modified: "2022/11/29"
tags: [defense_evasion, t1027, execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Invoke-Obfuscation Via Use MSHTA - PowerShell

### Description

Detects Obfuscated Powershell via use MSHTA in Scripts

```yml
title: Invoke-Obfuscation Via Use MSHTA - PowerShell
id: e55a5195-4724-480e-a77e-3ebe64bd3759
status: test
description: Detects Obfuscated Powershell via use MSHTA in Scripts
references:
    - https://github.com/SigmaHQ/sigma/issues/1009 # (Task31)
author: Nikita Nazarov, oscd.community
date: 2020/10/08
modified: 2022/11/29
tags:
    - attack.defense_evasion
    - attack.t1027
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection_4104:
        ScriptBlockText|contains|all:
            - 'set'
            - '&&'
            - 'mshta'
            - 'vbscript:createobject'
            - '.run'
            - '(window.close)'
    condition: selection_4104
falsepositives:
    - Unknown
level: high

```
