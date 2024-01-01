---
title: "LSASS Process Reconnaissance Via Findstr.EXE"
status: "experimental"
created: "2022/08/12"
last_modified: "2023/11/11"
tags: [credential_access, t1552_006, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## LSASS Process Reconnaissance Via Findstr.EXE

### Description

Detects findstring commands that include the keyword lsass, which indicates recon actviity for the LSASS process PID

```yml
title: LSASS Process Reconnaissance Via Findstr.EXE
id: fe63010f-8823-4864-a96b-a7b4a0f7b929
status: experimental
description: Detects findstring commands that include the keyword lsass, which indicates recon actviity for the LSASS process PID
references:
    - https://blog.talosintelligence.com/2022/08/recent-cyber-attack.html?m=1
author: Florian Roth (Nextron Systems)
date: 2022/08/12
modified: 2023/11/11
tags:
    - attack.credential_access
    - attack.t1552.006
logsource:
    category: process_creation
    product: windows
detection:
    selection_findstr_img:
        - Image|endswith:
              - '\find.exe'
              - '\findstr.exe'
        - OriginalFileName:
              - 'FIND.EXE'
              - 'FINDSTR.EXE'
    selection_findstr_cli:
        CommandLine|contains: 'lsass'
    selection_special:
        CommandLine|contains:
            - ' /i "lsass'
            - ' /i lsass.exe'
            - 'findstr "lsass'
            - 'findstr lsass'
            - 'findstr.exe "lsass'
            - 'findstr.exe lsass'
    condition: all of selection_findstr_* or selection_special
falsepositives:
    - Unknown
level: high

```