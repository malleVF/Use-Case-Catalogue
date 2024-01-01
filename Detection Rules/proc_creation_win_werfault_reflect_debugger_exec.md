---
title: "Potential ReflectDebugger Content Execution Via WerFault.EXE"
status: "experimental"
created: "2023/06/30"
last_modified: ""
tags: [execution, defense_evasion, t1036, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Potential ReflectDebugger Content Execution Via WerFault.EXE

### Description

Detects execution of "WerFault.exe" with the "-pr" commandline flag that is used to run files stored in the ReflectDebugger key which could be used to store the path to the malware in order to masquerade the execution flow

```yml
title: Potential ReflectDebugger Content Execution Via WerFault.EXE
id: fabfb3a7-3ce1-4445-9c7c-3c27f1051cdd
related:
    - id: 0cf2e1c6-8d10-4273-8059-738778f981ad
      type: derived
status: experimental
description: Detects execution of "WerFault.exe" with the "-pr" commandline flag that is used to run files stored in the ReflectDebugger key which could be used to store the path to the malware in order to masquerade the execution flow
references:
    - https://cocomelonc.github.io/malware/2022/11/02/malware-pers-18.html
    - https://www.hexacorn.com/blog/2018/08/31/beyond-good-ol-run-key-part-85/
author: X__Junior (Nextron Systems)
date: 2023/06/30
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1036
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        - Image|endswith: '\WerFault.exe'
        - OriginalFileName: 'WerFault.exe'
    selection_cli:
        CommandLine|contains: ' -pr '
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium

```
