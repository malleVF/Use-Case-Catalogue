---
title: "Suspicious Runscripthelper.exe"
status: "test"
created: "2020/10/09"
last_modified: "2022/07/11"
tags: [execution, t1059, defense_evasion, t1202, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Suspicious Runscripthelper.exe

### Description

Detects execution of powershell scripts via Runscripthelper.exe

```yml
title: Suspicious Runscripthelper.exe
id: eca49c87-8a75-4f13-9c73-a5a29e845f03
status: test
description: Detects execution of powershell scripts via Runscripthelper.exe
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Runscripthelper/
author: Victor Sergeev, oscd.community
date: 2020/10/09
modified: 2022/07/11
tags:
    - attack.execution
    - attack.t1059
    - attack.defense_evasion
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\Runscripthelper.exe'
        CommandLine|contains: 'surfacecheck'
    condition: selection
fields:
    - CommandLine
falsepositives:
    - Unknown
level: medium

```
