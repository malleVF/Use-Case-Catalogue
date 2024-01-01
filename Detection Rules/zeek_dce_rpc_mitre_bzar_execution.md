---
title: "MITRE BZAR Indicators for Execution"
status: "test"
created: "2020/03/19"
last_modified: "2021/11/27"
tags: [execution, t1047, t1053_002, t1569_002, detection_rule]
logsrc_product: "zeek"
logsrc_service: "dce_rpc"
level: "medium"
---

## MITRE BZAR Indicators for Execution

### Description

Windows DCE-RPC functions which indicate an execution techniques on the remote system. All credit for the Zeek mapping of the suspicious endpoint/operation field goes to MITRE

```yml
title: MITRE BZAR Indicators for Execution
id: b640c0b8-87f8-4daa-aef8-95a24261dd1d
status: test
description: 'Windows DCE-RPC functions which indicate an execution techniques on the remote system. All credit for the Zeek mapping of the suspicious endpoint/operation field goes to MITRE'
references:
    - https://github.com/mitre-attack/bzar#indicators-for-attck-execution
author: '@neu5ron, SOC Prime'
date: 2020/03/19
modified: 2021/11/27
tags:
    - attack.execution
    - attack.t1047
    - attack.t1053.002
    - attack.t1569.002
logsource:
    product: zeek
    service: dce_rpc
detection:
    op1:
        endpoint: 'JobAdd'
        operation: 'atsvc'
    op2:
        endpoint: 'ITaskSchedulerService'
        operation: 'SchRpcEnableTask'
    op3:
        endpoint: 'ITaskSchedulerService'
        operation: 'SchRpcRegisterTask'
    op4:
        endpoint: 'ITaskSchedulerService'
        operation: 'SchRpcRun'
    op5:
        endpoint: 'IWbemServices'
        operation: 'ExecMethod'
    op6:
        endpoint: 'IWbemServices'
        operation: 'ExecMethodAsync'
    op7:
        endpoint: 'svcctl'
        operation: 'CreateServiceA'
    op8:
        endpoint: 'svcctl'
        operation: 'CreateServiceW'
    op9:
        endpoint: 'svcctl'
        operation: 'StartServiceA'
    op10:
        endpoint: 'svcctl'
        operation: 'StartServiceW'
    condition: 1 of op*
falsepositives:
    - Windows administrator tasks or troubleshooting
    - Windows management scripts or software
level: medium

```
