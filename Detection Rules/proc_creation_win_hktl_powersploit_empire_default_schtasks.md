---
title: "HackTool - Default PowerSploit/Empire Scheduled Task Creation"
status: "test"
created: "2018/03/06"
last_modified: "2023/03/03"
tags: [execution, persistence, privilege_escalation, s0111, g0022, g0060, car_2013-08-001, t1053_005, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## HackTool - Default PowerSploit/Empire Scheduled Task Creation

### Description

Detects the creation of a schtask via PowerSploit or Empire Default Configuration.

```yml
title: HackTool - Default PowerSploit/Empire Scheduled Task Creation
id: 56c217c3-2de2-479b-990f-5c109ba8458f
status: test
description: Detects the creation of a schtask via PowerSploit or Empire Default Configuration.
references:
    - https://github.com/0xdeadbeefJERKY/PowerSploit/blob/8690399ef70d2cad10213575ac67e8fa90ddf7c3/Persistence/Persistence.psm1
    - https://github.com/EmpireProject/Empire/blob/08cbd274bef78243d7a8ed6443b8364acd1fc48b/lib/modules/powershell/persistence/userland/schtasks.py
author: Markus Neis, @Karneades
date: 2018/03/06
modified: 2023/03/03
tags:
    - attack.execution
    - attack.persistence
    - attack.privilege_escalation
    - attack.s0111
    - attack.g0022
    - attack.g0060
    - car.2013-08-001
    - attack.t1053.005
    - attack.t1059.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - '/Create'
            - 'powershell.exe -NonI'
            - '/TN Updater /TR'
        CommandLine|contains:
            - '/SC ONLOGON'
            - '/SC DAILY /ST'
            - '/SC ONIDLE'
            - '/SC HOURLY'
    condition: selection
falsepositives:
    - Unlikely
level: high

```