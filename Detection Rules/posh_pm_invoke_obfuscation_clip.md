---
title: "Invoke-Obfuscation CLIP+ Launcher - PowerShell Module"
status: "test"
created: "2020/10/13"
last_modified: "2022/12/02"
tags: [defense_evasion, t1027, execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Invoke-Obfuscation CLIP+ Launcher - PowerShell Module

### Description

Detects Obfuscated use of Clip.exe to execute PowerShell

```yml
title: Invoke-Obfuscation CLIP+ Launcher - PowerShell Module
id: a136cde0-61ad-4a61-9b82-8dc490e60dd2
related:
    - id: 73e67340-0d25-11eb-adc1-0242ac120002
      type: derived
status: test
description: Detects Obfuscated use of Clip.exe to execute PowerShell
references:
    - https://github.com/SigmaHQ/sigma/issues/1009  # (Task 26)
author: Jonathan Cheong, oscd.community
date: 2020/10/13
modified: 2022/12/02
tags:
    - attack.defense_evasion
    - attack.t1027
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: ps_module
    definition: 0ad03ef1-f21b-4a79-8ce8-e6900c54b65b
detection:
    selection_4103:
        Payload|re: '.*cmd.{0,5}(?:/c|/r).+clip(?:\.exe)?.{0,4}&&.+clipboard]::\(\s\\"\{\d\}.+-f.+"'
    condition: selection_4103
falsepositives:
    - Unknown
level: high

```
