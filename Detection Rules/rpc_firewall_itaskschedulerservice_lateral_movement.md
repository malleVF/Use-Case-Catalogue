---
title: "Remote Schedule Task Lateral Movement via ITaskSchedulerService"
status: "test"
created: "2022/01/01"
last_modified: "2022/01/01"
tags: [lateral_movement, t1053, t1053_002, detection_rule]
logsrc_product: "rpc_firewall"
logsrc_service: ""
level: "high"
---

## Remote Schedule Task Lateral Movement via ITaskSchedulerService

### Description

Detects remote RPC calls to create or execute a scheduled task

```yml
title: Remote Schedule Task Lateral Movement via ITaskSchedulerService
id: ace3ff54-e7fd-46bd-8ea0-74b49a0aca1d
status: test
description: Detects remote RPC calls to create or execute a scheduled task
references:
    - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/d1058a28-7e02-4948-8b8d-4a347fa64931
    - https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/ddd4608fe8684fcf2fcf9b48c5f0b3c28097f8a3/documents/MS-TSCH.md
    - https://github.com/zeronetworks/rpcfirewall
    - https://zeronetworks.com/blog/stopping-lateral-movement-via-the-rpc-firewall/
author: Sagie Dulce, Dekel Paz
date: 2022/01/01
modified: 2022/01/01
tags:
    - attack.lateral_movement
    - attack.t1053
    - attack.t1053.002
logsource:
    product: rpc_firewall
    category: application
    definition: 'Requirements: install and apply the RPC Firewall to all processes with "audit:true action:block uuid:86d35949-83c9-4044-b424-db363231fd0c"'
detection:
    selection:
        EventLog: RPCFW
        EventID: 3
        InterfaceUuid: 86d35949-83c9-4044-b424-db363231fd0c
        OpNum:
            - 1
            - 3
            - 4
            - 10
            - 11
            - 12
            - 13
            - 14
            - 15
    condition: selection
falsepositives:
    - Unknown
level: high

```