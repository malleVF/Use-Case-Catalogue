---
title: "Security Eventlog Cleared"
status: "test"
created: "2017/01/10"
last_modified: "2022/02/24"
tags: [defense_evasion, t1070_001, car_2016-04-002, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## Security Eventlog Cleared

### Description

One of the Windows Eventlogs has been cleared. e.g. caused by "wevtutil cl" command execution

```yml
title: Security Eventlog Cleared
id: d99b79d2-0a6f-4f46-ad8b-260b6e17f982
related:
    - id: f2f01843-e7b8-4f95-a35a-d23584476423
      type: obsoletes
    - id: a122ac13-daf8-4175-83a2-72c387be339d
      type: obsoletes
status: test
description: One of the Windows Eventlogs has been cleared. e.g. caused by "wevtutil cl" command execution
references:
    - https://twitter.com/deviouspolack/status/832535435960209408
    - https://www.hybrid-analysis.com/sample/027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745?environmentId=100
    - https://github.com/Azure/Azure-Sentinel/blob/f99542b94afe0ad2f19a82cc08262e7ac8e1428e/Detections/SecurityEvent/SecurityEventLogCleared.yaml
author: Florian Roth (Nextron Systems)
date: 2017/01/10
modified: 2022/02/24
tags:
    - attack.defense_evasion
    - attack.t1070.001
    - car.2016-04-002
logsource:
    product: windows
    service: security
detection:
    selection_517:
        EventID: 517
        Provider_Name: Security
    selection_1102:
        EventID: 1102
        Provider_Name: Microsoft-Windows-Eventlog
    condition: 1 of selection_*
falsepositives:
    - Rollout of log collection agents (the setup routine often includes a reset of the local Eventlog)
    - System provisioning (system reset before the golden image creation)
level: high

```