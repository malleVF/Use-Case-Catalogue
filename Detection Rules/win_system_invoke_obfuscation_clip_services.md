---
title: "Invoke-Obfuscation CLIP+ Launcher - System"
status: "experimental"
created: "2020/10/13"
last_modified: "2023/02/20"
tags: [defense_evasion, t1027, execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: "system"
level: "high"
---

## Invoke-Obfuscation CLIP+ Launcher - System

### Description

Detects Obfuscated use of Clip.exe to execute PowerShell

```yml
title: Invoke-Obfuscation CLIP+ Launcher - System
id: f7385ee2-0e0c-11eb-adc1-0242ac120002
status: experimental
description: Detects Obfuscated use of Clip.exe to execute PowerShell
references:
    - https://github.com/SigmaHQ/sigma/issues/1009  # (Task 26)
author: Jonathan Cheong, oscd.community
date: 2020/10/13
modified: 2023/02/20
tags:
    - attack.defense_evasion
    - attack.t1027
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
        ImagePath|contains|all:
            - 'cmd'
            - '&&'
            - 'clipboard]::'
    condition: selection
falsepositives:
    - Unknown
level: high

```
