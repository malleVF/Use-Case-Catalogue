---
title: "Password Provided In Command Line Of Net.EXE"
status: "test"
created: "2021/12/09"
last_modified: "2023/02/21"
tags: [defense_evasion, initial_access, persistence, privilege_escalation, lateral_movement, t1021_002, t1078, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Password Provided In Command Line Of Net.EXE

### Description

Detects a when net.exe is called with a password in the command line

```yml
title: Password Provided In Command Line Of Net.EXE
id: d4498716-1d52-438f-8084-4a603157d131
status: test
description: Detects a when net.exe is called with a password in the command line
references:
    - Internal Research
author: Tim Shelton (HAWK.IO)
date: 2021/12/09
modified: 2023/02/21
tags:
    - attack.defense_evasion
    - attack.initial_access
    - attack.persistence
    - attack.privilege_escalation
    - attack.lateral_movement
    - attack.t1021.002
    - attack.t1078
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\net.exe'
              - '\net1.exe'
        - OriginalFileName:
              - 'net.exe'
              - 'net1.exe'
    selection_cli:
        CommandLine|contains|all:
            - ' use '
            - ':*\\'
            - '/USER:* *'
    filter_empty:
        CommandLine|endswith: ' '
    condition: all of selection_* and not 1 of filter*
falsepositives:
    - Unknown
level: medium

```
