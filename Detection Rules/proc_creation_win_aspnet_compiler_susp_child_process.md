---
title: "Suspicious Child Process of AspNetCompiler"
status: "experimental"
created: "2023/08/14"
last_modified: ""
tags: [defense_evasion, t1127, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious Child Process of AspNetCompiler

### Description

Detects potentially suspicious child processes of "aspnet_compiler.exe".

```yml
title: Suspicious Child Process of AspNetCompiler
id: 9ccba514-7cb6-4c5c-b377-700758f2f120 # SuspChild
related:
    - id: 4c7f49ee-2638-43bb-b85b-ce676c30b260 # TMP File
      type: similar
    - id: 9f50fe98-fe5c-4a2d-86c7-fad7f63ed622 # Susp Paths
      type: similar
    - id: a01b8329-5953-4f73-ae2d-aa01e1f35f00 # Exec
      type: similar
status: experimental
description: Detects potentially suspicious child processes of "aspnet_compiler.exe".
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Aspnet_Compiler/
    - https://ijustwannared.team/2020/08/01/the-curious-case-of-aspnet_compiler-exe/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/08/14
tags:
    - attack.defense_evasion
    - attack.t1127
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\aspnet_compiler.exe'
    selection_child:
        # Note: add other potential suspicious child processes and paths
        - Image|endswith:
              - '\calc.exe'
              - '\notepad.exe'
        - Image|contains:
              - '\Users\Public\'
              - '\AppData\Local\Temp\'
              - '\AppData\Local\Roaming\'
              - ':\Temp\'
              - ':\Windows\Temp\'
              - ':\Windows\System32\Tasks\'
              - ':\Windows\Tasks\'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high

```