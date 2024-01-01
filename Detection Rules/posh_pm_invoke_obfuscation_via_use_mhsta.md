---
title: "Invoke-Obfuscation Via Use MSHTA - PowerShell Module"
status: "test"
created: "2020/10/08"
last_modified: "2023/01/04"
tags: [defense_evasion, t1027, execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Invoke-Obfuscation Via Use MSHTA - PowerShell Module

### Description

Detects Obfuscated Powershell via use MSHTA in Scripts

```yml
title: Invoke-Obfuscation Via Use MSHTA - PowerShell Module
id: 07ad2ea8-6a55-4ac6-bf3e-91b8e59676eb
related:
    - id: e55a5195-4724-480e-a77e-3ebe64bd3759
      type: derived
status: test
description: Detects Obfuscated Powershell via use MSHTA in Scripts
references:
    - https://github.com/SigmaHQ/sigma/issues/1009 # (Task31)
author: Nikita Nazarov, oscd.community
date: 2020/10/08
modified: 2023/01/04
tags:
    - attack.defense_evasion
    - attack.t1027
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: ps_module
    definition: 0ad03ef1-f21b-4a79-8ce8-e6900c54b65b
detection:
    selection:
        Payload|contains|all:
            - 'set'
            - '&&'
            - 'mshta'
            - 'vbscript:createobject'
            - '.run'
            - '(window.close)'
    condition: selection
falsepositives:
    - Unknown
level: high

```
