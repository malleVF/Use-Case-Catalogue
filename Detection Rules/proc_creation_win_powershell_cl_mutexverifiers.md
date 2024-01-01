---
title: "Potential Script Proxy Execution Via CL_Mutexverifiers.ps1"
status: "experimental"
created: "2022/05/21"
last_modified: "2023/08/17"
tags: [defense_evasion, t1216, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Potential Script Proxy Execution Via CL_Mutexverifiers.ps1

### Description

Detects the use of the Microsoft signed script "CL_mutexverifiers" to proxy the execution of additional PowerShell script commands

```yml
title: Potential Script Proxy Execution Via CL_Mutexverifiers.ps1
id: 1e0e1a81-e79b-44bc-935b-ddb9c8006b3d
status: experimental
description: Detects the use of the Microsoft signed script "CL_mutexverifiers" to proxy the execution of additional PowerShell script commands
references:
    - https://lolbas-project.github.io/lolbas/Scripts/CL_mutexverifiers/
author: Nasreddine Bencherchali (Nextron Systems), oscd.community, Natalia Shornikova, frack113
date: 2022/05/21
modified: 2023/08/17
tags:
    - attack.defense_evasion
    - attack.t1216
logsource:
    category: process_creation
    product: windows
detection:
    selection_pwsh:
        ParentImage|endswith:
            # Note: to avoid potential FPs we assume the script was launched from powershell. But in theory it can be launched by any Powershell like process
            - '\powershell.exe'
            - '\pwsh.exe'
        Image|endswith: '\powershell.exe'
        CommandLine|contains: ' -nologo -windowstyle minimized -file '
    selection_temp:
        # Note: Since the function uses "env:temp" the value will change depending on the context of exec
        CommandLine|contains:
            - '\AppData\Local\Temp\'
            - '\Windows\Temp\'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium

```