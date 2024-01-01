---
title: "CMSTP Execution Registry Event"
status: "stable"
created: "2018/07/16"
last_modified: "2020/12/23"
tags: [defense_evasion, execution, t1218_003, g0069, car_2019-04-001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## CMSTP Execution Registry Event

### Description

Detects various indicators of Microsoft Connection Manager Profile Installer execution

```yml
title: CMSTP Execution Registry Event
id: b6d235fc-1d38-4b12-adbe-325f06728f37
status: stable
description: Detects various indicators of Microsoft Connection Manager Profile Installer execution
references:
    - https://web.archive.org/web/20190720093911/http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/
author: Nik Seetharaman
date: 2018/07/16
modified: 2020/12/23
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1218.003
    - attack.g0069
    - car.2019-04-001
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        TargetObject|contains: '\cmmgr32.exe'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
    - Details
falsepositives:
    - Legitimate CMSTP use (unlikely in modern enterprise environments)
level: high

```
