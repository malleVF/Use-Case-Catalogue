---
title: "MITRE BZAR Indicators for Persistence"
status: "test"
created: "2020/03/19"
last_modified: "2021/11/27"
tags: [persistence, t1547_004, detection_rule]
logsrc_product: "zeek"
logsrc_service: "dce_rpc"
level: "medium"
---

## MITRE BZAR Indicators for Persistence

### Description

Windows DCE-RPC functions which indicate a persistence techniques on the remote system. All credit for the Zeek mapping of the suspicious endpoint/operation field goes to MITRE.

```yml
title: MITRE BZAR Indicators for Persistence
id: 53389db6-ba46-48e3-a94c-e0f2cefe1583
status: test
description: 'Windows DCE-RPC functions which indicate a persistence techniques on the remote system. All credit for the Zeek mapping of the suspicious endpoint/operation field goes to MITRE.'
references:
    - https://github.com/mitre-attack/bzar#indicators-for-attck-persistence
author: '@neu5ron, SOC Prime'
date: 2020/03/19
modified: 2021/11/27
tags:
    - attack.persistence
    - attack.t1547.004
logsource:
    product: zeek
    service: dce_rpc
detection:
    op1:
        endpoint: 'spoolss'
        operation: 'RpcAddMonitor'
    op2:
        endpoint: 'spoolss'
        operation: 'RpcAddPrintProcessor'
    op3:
        endpoint: 'IRemoteWinspool'
        operation: 'RpcAsyncAddMonitor'
    op4:
        endpoint: 'IRemoteWinspool'
        operation: 'RpcAsyncAddPrintProcessor'
    op5:
        endpoint: 'ISecLogon'
        operation: 'SeclCreateProcessWithLogonW'
    op6:
        endpoint: 'ISecLogon'
        operation: 'SeclCreateProcessWithLogonExW'
    condition: 1 of op*
falsepositives:
    - Windows administrator tasks or troubleshooting
    - Windows management scripts or software
level: medium

```
