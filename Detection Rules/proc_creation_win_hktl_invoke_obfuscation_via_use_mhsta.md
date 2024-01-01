---
title: "Invoke-Obfuscation Via Use MSHTA"
status: "test"
created: "2020/10/08"
last_modified: "2022/03/08"
tags: [defense_evasion, t1027, execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Invoke-Obfuscation Via Use MSHTA

### Description

Detects Obfuscated Powershell via use MSHTA in Scripts

```yml
title: Invoke-Obfuscation Via Use MSHTA
id: ac20ae82-8758-4f38-958e-b44a3140ca88
status: test
description: Detects Obfuscated Powershell via use MSHTA in Scripts
references:
    - https://github.com/SigmaHQ/sigma/issues/1009   # (Task31)
author: Nikita Nazarov, oscd.community
date: 2020/10/08
modified: 2022/03/08
tags:
    - attack.defense_evasion
    - attack.t1027
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
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
