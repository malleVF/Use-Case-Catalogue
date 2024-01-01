---
title: "Scheduled Task Creation"
status: "test"
created: "2019/01/16"
last_modified: "2022/10/09"
tags: [execution, persistence, privilege_escalation, t1053_005, s0111, car_2013-08-001, stp_1u, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "low"
---

## Scheduled Task Creation

### Description

Detects the creation of scheduled tasks in user session

```yml
title: Scheduled Task Creation
id: 92626ddd-662c-49e3-ac59-f6535f12d189
status: test
description: Detects the creation of scheduled tasks in user session
author: Florian Roth (Nextron Systems)
date: 2019/01/16
modified: 2022/10/09
tags:
    - attack.execution
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1053.005
    - attack.s0111
    - car.2013-08-001
    - stp.1u
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains: ' /create '
    filter:
        User|contains: # covers many language settings
            - 'AUTHORI'
            - 'AUTORI'
    condition: selection and not filter
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Administrative activity
    - Software installation
level: low

```
