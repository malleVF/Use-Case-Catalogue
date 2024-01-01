---
title: "Operator Bloopers Cobalt Strike Modules"
status: "test"
created: "2022/05/06"
last_modified: "2023/01/30"
tags: [execution, t1059_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Operator Bloopers Cobalt Strike Modules

### Description

Detects Cobalt Strike module/commands accidentally entered in CMD shell

```yml
title: Operator Bloopers Cobalt Strike Modules
id: 4f154fb6-27d1-4813-a759-78b93e0b9c48
related:
    - id: 647c7b9e-d784-4fda-b9a0-45c565a7b729
      type: similar
status: test
description: Detects Cobalt Strike module/commands accidentally entered in CMD shell
references:
    - https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/cobalt-4-5-user-guide.pdf
    - https://thedfirreport.com/2021/10/04/bazarloader-and-the-conti-leaks/
    - https://thedfirreport.com/2022/06/16/sans-ransomware-summit-2022-can-you-detect-this/
author: _pete_0, TheDFIRReport
date: 2022/05/06
modified: 2023/01/30
tags:
    - attack.execution
    - attack.t1059.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - OriginalFileName: 'Cmd.Exe'
        - Image|endswith: '\cmd.exe'
    selection_cli:
        CommandLine|contains:
            - 'Invoke-UserHunter'
            - 'Invoke-ShareFinder'
            - 'Invoke-Kerberoast'
            - 'Invoke-SMBAutoBrute'
            - 'Invoke-Nightmare'
            - 'zerologon'
            - 'av_query'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high

```