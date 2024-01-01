---
title: "RemCom Service Installation"
status: "experimental"
created: "2023/08/07"
last_modified: ""
tags: [execution, t1569_002, detection_rule]
logsrc_product: "windows"
logsrc_service: "system"
level: "medium"
---

## RemCom Service Installation

### Description

Detects RemCom service installation and execution events

```yml
title: RemCom Service Installation
id: 9e36ed87-4986-482e-8e3b-5c23ffff11bf
status: experimental
description: Detects RemCom service installation and execution events
references:
    - https://github.com/kavika13/RemCom/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/08/07
tags:
    - attack.execution
    - attack.t1569.002
logsource:
    product: windows
    service: system
detection:
    selection_eid:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
    selection_service:
        - ServiceName: 'RemComSvc'
        - ImagePath|endswith: '\RemComSvc.exe'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium

```
