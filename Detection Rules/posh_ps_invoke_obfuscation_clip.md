---
title: "Invoke-Obfuscation CLIP+ Launcher - PowerShell"
status: "test"
created: "2020/10/13"
last_modified: "2022/12/02"
tags: [defense_evasion, t1027, execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Invoke-Obfuscation CLIP+ Launcher - PowerShell

### Description

Detects Obfuscated use of Clip.exe to execute PowerShell

```yml
title: Invoke-Obfuscation CLIP+ Launcher - PowerShell
id: 73e67340-0d25-11eb-adc1-0242ac120002
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
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection_4104:
        ScriptBlockText|re: '.*cmd.{0,5}(?:/c|/r).+clip(?:\.exe)?.{0,4}&&.+clipboard]::\(\s\\"\{\d\}.+-f.+"'
    condition: selection_4104
falsepositives:
    - Unknown
level: high

```