---
title: "PowerShell ShellCode"
status: "test"
created: "2018/11/17"
last_modified: "2022/12/25"
tags: [defense_evasion, privilege_escalation, t1055, execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## PowerShell ShellCode

### Description

Detects Base64 encoded Shellcode

```yml
title: PowerShell ShellCode
id: 16b37b70-6fcf-4814-a092-c36bd3aafcbd
status: test
description: Detects Base64 encoded Shellcode
references:
    - https://twitter.com/cyb3rops/status/1063072865992523776
author: David Ledbetter (shellcode), Florian Roth (Nextron Systems)
date: 2018/11/17
modified: 2022/12/25
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1055
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains: 'AAAAYInlM'
    selection2:
        ScriptBlockText|contains:
            - 'OiCAAAAYInlM'
            - 'OiJAAAAYInlM'
    condition: selection and selection2
falsepositives:
    - Unknown
level: high

```
