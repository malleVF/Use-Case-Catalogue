---
title: "Remote Schedule Task Lateral Movement via ATSvc"
status: "test"
created: "2022/01/01"
last_modified: "2022/01/01"
tags: [lateral_movement, t1053, t1053_002, detection_rule]
logsrc_product: "rpc_firewall"
logsrc_service: ""
level: "high"
---

## Remote Schedule Task Lateral Movement via ATSvc

### Description

Detects remote RPC calls to create or execute a scheduled task via ATSvc

```yml
title: Remote Schedule Task Lateral Movement via ATSvc
id: 0fcd1c79-4eeb-4746-aba9-1b458f7a79cb
status: test
description: Detects remote RPC calls to create or execute a scheduled task via ATSvc
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
    definition: 'Requirements: install and apply the RPC Firewall to all processes with "audit:true action:block uuid:1ff70682-0a51-30e8-076d-740be8cee98b"'
detection:
    selection:
        EventLog: RPCFW
        EventID: 3
        InterfaceUuid: 1ff70682-0a51-30e8-076d-740be8cee98b
        OpNum:
            - 0
            - 1
    condition: selection
falsepositives:
    - Unknown
level: high

```