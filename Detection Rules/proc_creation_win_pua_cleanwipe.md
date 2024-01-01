---
title: "PUA - CleanWipe Execution"
status: "experimental"
created: "2021/12/18"
last_modified: "2023/02/14"
tags: [defense_evasion, t1562_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## PUA - CleanWipe Execution

### Description

Detects the use of CleanWipe a tool usually used to delete Symantec antivirus.

```yml
title: PUA - CleanWipe Execution
id: f44800ac-38ec-471f-936e-3fa7d9c53100
status: experimental
description: Detects the use of CleanWipe a tool usually used to delete Symantec antivirus.
references:
    - https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Other/CleanWipe
author: Nasreddine Bencherchali (Nextron Systems)
date: 2021/12/18
modified: 2023/02/14
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Image|endswith: '\SepRemovalToolNative_x64.exe'
    selection2:
        Image|endswith: '\CATClean.exe'
        CommandLine|contains: '--uninstall'
    selection3:
        Image|endswith: '\NetInstaller.exe'
        CommandLine|contains: '-r'
    selection4:
        Image|endswith: '\WFPUnins.exe'
        CommandLine|contains|all:
            - '/uninstall'
            - '/enterprise'
    condition: 1 of selection*
falsepositives:
    - Legitimate administrative use (Should be investigated either way)
level: high

```