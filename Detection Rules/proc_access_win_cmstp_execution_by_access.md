---
title: "CMSTP Execution Process Access"
status: "stable"
created: "2018/07/16"
last_modified: "2021/06/27"
tags: [defense_evasion, t1218_003, execution, t1559_001, g0069, g0080, car_2019-04-001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## CMSTP Execution Process Access

### Description

Detects various indicators of Microsoft Connection Manager Profile Installer execution

```yml
title: CMSTP Execution Process Access
id: 3b4b232a-af90-427c-a22f-30b0c0837b95
status: stable
description: Detects various indicators of Microsoft Connection Manager Profile Installer execution
references:
    - https://web.archive.org/web/20190720093911/http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/
author: Nik Seetharaman
date: 2018/07/16
modified: 2021/06/27
tags:
    - attack.defense_evasion
    - attack.t1218.003
    - attack.execution
    - attack.t1559.001
    - attack.g0069
    - attack.g0080
    - car.2019-04-001
logsource:
    product: windows
    category: process_access
detection:
    # Process Access Call Trace
    selection:
        CallTrace|contains: 'cmlua.dll'
    condition: selection
falsepositives:
    - Legitimate CMSTP use (unlikely in modern enterprise environments)
level: high

```
