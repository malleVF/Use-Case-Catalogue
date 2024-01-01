---
title: "Invoke-Obfuscation Via Use Rundll32 - PowerShell"
status: "test"
created: "2019/10/08"
last_modified: "2022/11/29"
tags: [defense_evasion, t1027, execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Invoke-Obfuscation Via Use Rundll32 - PowerShell

### Description

Detects Obfuscated Powershell via use Rundll32 in Scripts

```yml
title: Invoke-Obfuscation Via Use Rundll32 - PowerShell
id: a5a30a6e-75ca-4233-8b8c-42e0f2037d3b
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
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection_4104:
        ScriptBlockText|contains|all:
            - '&&'
            - 'rundll32'
            - 'shell32.dll'
            - 'shellexec_rundll'
        ScriptBlockText|contains:
            - 'value'
            - 'invoke'
            - 'comspec'
            - 'iex'
    condition: selection_4104
falsepositives:
    - Unknown
level: high

```