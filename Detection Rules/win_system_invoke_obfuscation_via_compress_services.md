---
title: "Invoke-Obfuscation COMPRESS OBFUSCATION - System"
status: "test"
created: "2020/10/18"
last_modified: "2022/11/29"
tags: [defense_evasion, t1027, execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: "system"
level: "medium"
---

## Invoke-Obfuscation COMPRESS OBFUSCATION - System

### Description

Detects Obfuscated Powershell via COMPRESS OBFUSCATION

```yml
title: Invoke-Obfuscation COMPRESS OBFUSCATION - System
id: 175997c5-803c-4b08-8bb0-70b099f47595
status: test
description: Detects Obfuscated Powershell via COMPRESS OBFUSCATION
references:
    - https://github.com/SigmaHQ/sigma/issues/1009 # (Task 19)
author: Timur Zinniatullin, oscd.community
date: 2020/10/18
modified: 2022/11/29
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
            - 'new-object'
            - 'text.encoding]::ascii'
            - 'readtoend'
        ImagePath|contains:
            - ':system.io.compression.deflatestream'
            - 'system.io.streamreader'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
