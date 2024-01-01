---
title: "LSA PPL Protection Disabled Via Reg.EXE"
status: "experimental"
created: "2022/03/22"
last_modified: "2023/03/26"
tags: [defense_evasion, t1562_010, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## LSA PPL Protection Disabled Via Reg.EXE

### Description

Detects the usage of the "reg.exe" utility to disable PPL protection on the LSA process

```yml
title: LSA PPL Protection Disabled Via Reg.EXE
id: 8c0eca51-0f88-4db2-9183-fdfb10c703f9
status: experimental
description: Detects the usage of the "reg.exe" utility to disable PPL protection on the LSA process
references:
    - https://thedfirreport.com/2022/03/21/apt35-automates-initial-access-using-proxyshell/
author: Florian Roth (Nextron Systems)
date: 2022/03/22
modified: 2023/03/26
tags:
    - attack.defense_evasion
    - attack.t1562.010
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\reg.exe'
        - OriginalFileName: 'reg.exe'
    selection_cli:
        CommandLine|contains: 'SYSTEM\CurrentControlSet\Control\Lsa'
        CommandLine|contains|all:
            - ' add '
            - ' /d 0'
            - ' /v RunAsPPL '
    condition: all of selection_*
falsepositives:
    - Unlikely
level: high

```
