---
title: "Invoke-Obfuscation VAR+ Launcher - PowerShell Module"
status: "test"
created: "2020/10/15"
last_modified: "2022/12/02"
tags: [defense_evasion, t1027, execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Invoke-Obfuscation VAR+ Launcher - PowerShell Module

### Description

Detects Obfuscated use of Environment Variables to execute PowerShell

```yml
title: Invoke-Obfuscation VAR+ Launcher - PowerShell Module
id: 6bfb8fa7-b2e7-4f6c-8d9d-824e5d06ea9e
related:
    - id: 0adfbc14-0ed1-11eb-adc1-0242ac120002
      type: derived
status: test
description: Detects Obfuscated use of Environment Variables to execute PowerShell
references:
    - https://github.com/SigmaHQ/sigma/issues/1009  # (Task 24)
author: Jonathan Cheong, oscd.community
date: 2020/10/15
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
        Payload|re: '.*cmd.{0,5}(?:/c|/r)(?:\s|)"set\s[a-zA-Z]{3,6}.*(?:\{\d\}){1,}\\"\s+?-f(?:.*\)){1,}.*"'
    condition: selection_4103
falsepositives:
    - Unknown
level: high

```
