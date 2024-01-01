---
title: "Process Memory Dump Via Comsvcs.DLL"
status: "test"
created: "2020/02/18"
last_modified: "2023/05/16"
tags: [defense_evasion, credential_access, t1036, t1003_001, car_2013-05-009, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Process Memory Dump Via Comsvcs.DLL

### Description

Detects a process memory dump via "comsvcs.dll" using rundll32, covering multiple different techniques (ordinal, minidump function, etc.)

```yml
title: Process Memory Dump Via Comsvcs.DLL
id: 646ea171-dded-4578-8a4d-65e9822892e3
related:
    - id: 09e6d5c0-05b8-4ff8-9eeb-043046ec774c
      type: obsoletes
status: test
description: Detects a process memory dump via "comsvcs.dll" using rundll32, covering multiple different techniques (ordinal, minidump function, etc.)
references:
    - https://twitter.com/shantanukhande/status/1229348874298388484
    - https://twitter.com/pythonresponder/status/1385064506049630211?s=21
    - https://twitter.com/Hexacorn/status/1224848930795552769
    - https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/
    - https://twitter.com/SBousseaden/status/1167417096374050817
    - https://twitter.com/Wietze/status/1542107456507203586
    - https://github.com/Hackndo/lsassy/blob/14d8f8ae596ecf22b449bfe919829173b8a07635/lsassy/dumpmethod/comsvcs.py
author: Florian Roth (Nextron Systems), Modexp, Nasreddine Bencherchali (Nextron Systems)
date: 2020/02/18
modified: 2023/05/16
tags:
    - attack.defense_evasion
    - attack.credential_access
    - attack.t1036
    - attack.t1003.001
    - car.2013-05-009
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\rundll32.exe'
        - OriginalFileName: 'RUNDLL32.EXE'
        - CommandLine|contains: 'rundll32'
    selection_cli_1:
        CommandLine|contains|all:
            - 'comsvcs'
            - 'full'
        CommandLine|contains:
            - '#-'
            - '#+'
            - '#24'
            - '24 '
            - 'MiniDump' # Matches MiniDump and MinidumpW
    selection_generic:
        CommandLine|contains|all:
            - '24'
            - 'comsvcs'
            - 'full'
        CommandLine|contains:
            - ' #'
            - ',#'
            - ', #'
    condition: (selection_img and 1 of selection_cli_*) or selection_generic
falsepositives:
    - Unlikely
level: high

```