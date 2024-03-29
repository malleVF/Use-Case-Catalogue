---
title: "RottenPotato Like Attack Pattern"
status: "test"
created: "2019/11/15"
last_modified: "2022/12/22"
tags: [privilege_escalation, credential_access, t1557_001, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## RottenPotato Like Attack Pattern

### Description

Detects logon events that have characteristics of events generated during an attack with RottenPotato and the like

```yml
title: RottenPotato Like Attack Pattern
id: 16f5d8ca-44bd-47c8-acbe-6fc95a16c12f
status: test
description: Detects logon events that have characteristics of events generated during an attack with RottenPotato and the like
references:
    - https://twitter.com/SBousseaden/status/1195284233729777665
author: '@SBousseaden, Florian Roth'
date: 2019/11/15
modified: 2022/12/22
tags:
    - attack.privilege_escalation
    - attack.credential_access
    - attack.t1557.001
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 3
        TargetUserName: 'ANONYMOUS LOGON'
        WorkstationName: '-'
        IpAddress:
            - '127.0.0.1'
            - '::1'
    condition: selection
falsepositives:
    - Unknown
level: high

```
