---
title: "Remote PowerShell Session (PS Classic)"
status: "test"
created: "2019/08/10"
last_modified: "2023/10/27"
tags: [execution, t1059_001, lateral_movement, t1021_006, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Remote PowerShell Session (PS Classic)

### Description

Detects remote PowerShell sessions

```yml
title: Remote PowerShell Session (PS Classic)
id: 60167e5c-84b2-4c95-a7ac-86281f27c445
related:
    - id: 96b9f619-aa91-478f-bacb-c3e50f8df575
      type: derived
status: test
description: Detects remote PowerShell sessions
references:
    - https://threathunterplaybook.com/hunts/windows/190511-RemotePwshExecution/notebook.html
author: Roberto Rodriguez @Cyb3rWard0g
date: 2019/08/10
modified: 2023/10/27
tags:
    - attack.execution
    - attack.t1059.001
    - attack.lateral_movement
    - attack.t1021.006
logsource:
    product: windows
    category: ps_classic_start
detection:
    selection:
        Data|contains|all:
            - 'HostName=ServerRemoteHost'
            - 'wsmprovhost.exe'
    condition: selection
falsepositives:
    - Legitimate use remote PowerShell sessions
level: high

```
