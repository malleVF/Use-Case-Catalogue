---
title: "Invoke-Obfuscation Via Use Rundll32 - PowerShell Module"
status: "test"
created: "2019/10/08"
last_modified: "2022/11/29"
tags: [defense_evasion, t1027, execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Invoke-Obfuscation Via Use Rundll32 - PowerShell Module

### Description

Detects Obfuscated Powershell via use Rundll32 in Scripts

```yml
title: Invoke-Obfuscation Via Use Rundll32 - PowerShell Module
id: 88a22f69-62f9-4b8a-aa00-6b0212f2f05a
related:
    - id: a5a30a6e-75ca-4233-8b8c-42e0f2037d3b
      type: derived
status: test
description: Detects Obfuscated Powershell via use Rundll32 in Scripts
references:
    - https://github.com/SigmaHQ/sigma/issues/1009
author: Nikita Nazarov, oscd.community
date: 2019/10/08
modified: 2022/11/29
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
    selection_4103:
        Payload|contains|all:
            - '&&'
            - 'rundll32'
            - 'shell32.dll'
            - 'shellexec_rundll'
        Payload|contains:
            - 'value'
            - 'invoke'
            - 'comspec'
            - 'iex'
    condition: selection_4103
falsepositives:
    - Unknown
level: high

```