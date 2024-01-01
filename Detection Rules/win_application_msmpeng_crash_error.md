---
title: "Microsoft Malware Protection Engine Crash"
status: "experimental"
created: "2017/05/09"
last_modified: "2023/04/14"
tags: [defense_evasion, t1211, t1562_001, detection_rule]
logsrc_product: "windows"
logsrc_service: "application"
level: "high"
---

## Microsoft Malware Protection Engine Crash

### Description

This rule detects a suspicious crash of the Microsoft Malware Protection Engine

```yml
title: Microsoft Malware Protection Engine Crash
id: 545a5da6-f103-4919-a519-e9aec1026ee4
related:
    - id: 6c82cf5c-090d-4d57-9188-533577631108
      type: similar
status: experimental
description: This rule detects a suspicious crash of the Microsoft Malware Protection Engine
references:
    - https://bugs.chromium.org/p/project-zero/issues/detail?id=1252&desc=5
    - https://technet.microsoft.com/en-us/library/security/4022344
author: Florian Roth (Nextron Systems)
date: 2017/05/09
modified: 2023/04/14
tags:
    - attack.defense_evasion
    - attack.t1211
    - attack.t1562.001
logsource:
    product: windows
    service: application
    # warning: The 'data' field used in the detection section is the container for the event data as a whole. You may have to adapt the rule for your backend accordingly
detection:
    selection:
        Provider_Name: 'Application Error'
        EventID: 1000
        Data|contains|all:
            - 'MsMpEng.exe'
            - 'mpengine.dll'
    condition: selection
falsepositives:
    - MsMpEng might crash if the "C:\" partition is full
level: high

```
