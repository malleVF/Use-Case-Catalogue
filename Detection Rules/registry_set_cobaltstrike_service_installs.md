---
title: "CobaltStrike Service Installations in Registry"
status: "test"
created: "2021/06/29"
last_modified: "2023/08/17"
tags: [execution, privilege_escalation, lateral_movement, t1021_002, t1543_003, t1569_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "critical"
---

## CobaltStrike Service Installations in Registry

### Description

Detects known malicious service installs that appear in cases in which a Cobalt Strike beacon elevates privileges or lateral movement.
We can also catch this by system log 7045 (https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/win_cobaltstrike_service_installs.yml)
In some SIEM you can catch those events also in HKLM\System\ControlSet001\Services or HKLM\System\ControlSet002\Services, however, this rule is based on a regular sysmon's events.


```yml
title: CobaltStrike Service Installations in Registry
id: 61a7697c-cb79-42a8-a2ff-5f0cdfae0130
status: test
description: |
    Detects known malicious service installs that appear in cases in which a Cobalt Strike beacon elevates privileges or lateral movement.
    We can also catch this by system log 7045 (https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/win_cobaltstrike_service_installs.yml)
    In some SIEM you can catch those events also in HKLM\System\ControlSet001\Services or HKLM\System\ControlSet002\Services, however, this rule is based on a regular sysmon's events.
references:
    - https://www.sans.org/webcasts/tech-tuesday-workshop-cobalt-strike-detection-log-analysis-119395
author: Wojciech Lesicki
date: 2021/06/29
modified: 2023/08/17
tags:
    - attack.execution
    - attack.privilege_escalation
    - attack.lateral_movement
    - attack.t1021.002
    - attack.t1543.003
    - attack.t1569.002
logsource:
    category: registry_set
    product: windows
detection:
    main:
        TargetObject|contains: 'HKLM\System\CurrentControlSet\Services'
    selection_1:
        Details|contains|all:
            - 'ADMIN$'
            - '.exe'
    selection_2:
        Details|contains|all:
            - '%COMSPEC%'
            - 'start'
            - 'powershell'
    condition: main and 1 of selection_*
falsepositives:
    - Unknown
level: critical

```
