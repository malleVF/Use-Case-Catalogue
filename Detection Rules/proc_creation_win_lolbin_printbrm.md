---
title: "PrintBrm ZIP Creation of Extraction"
status: "test"
created: "2022/05/02"
last_modified: ""
tags: [command_and_control, t1105, defense_evasion, t1564_004, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## PrintBrm ZIP Creation of Extraction

### Description

Detects the execution of the LOLBIN PrintBrm.exe, which can be used to create or extract ZIP files. PrintBrm.exe should not be run on a normal workstation.

```yml
title: PrintBrm ZIP Creation of Extraction
id: cafeeba3-01da-4ab4-b6c4-a31b1d9730c7
status: test
description: Detects the execution of the LOLBIN PrintBrm.exe, which can be used to create or extract ZIP files. PrintBrm.exe should not be run on a normal workstation.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/PrintBrm/
author: frack113
date: 2022/05/02
tags:
    - attack.command_and_control
    - attack.t1105
    - attack.defense_evasion
    - attack.t1564.004
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\PrintBrm.exe'
        CommandLine|contains|all:
            - ' -f'
            - '.zip'
    condition: selection
falsepositives:
    - Unknown
level: high

```
