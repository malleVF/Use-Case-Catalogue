---
title: "Hijack Legit RDP Session to Move Laterally"
status: "test"
created: "2019/02/21"
last_modified: "2021/11/27"
tags: [command_and_control, t1219, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Hijack Legit RDP Session to Move Laterally

### Description

Detects the usage of tsclient share to place a backdoor on the RDP source machine's startup folder

```yml
title: Hijack Legit RDP Session to Move Laterally
id: 52753ea4-b3a0-4365-910d-36cff487b789
status: test
description: Detects the usage of tsclient share to place a backdoor on the RDP source machine's startup folder
author: Samir Bousseaden
date: 2019/02/21
modified: 2021/11/27
tags:
    - attack.command_and_control
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        Image|endswith: '\mstsc.exe'
        TargetFilename|contains: '\Microsoft\Windows\Start Menu\Programs\Startup\'
    condition: selection
falsepositives:
    - Unlikely
level: high

```
