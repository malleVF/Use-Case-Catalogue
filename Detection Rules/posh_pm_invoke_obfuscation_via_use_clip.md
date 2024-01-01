---
title: "Invoke-Obfuscation Via Use Clip - PowerShell Module"
status: "test"
created: "2020/10/09"
last_modified: "2022/11/29"
tags: [defense_evasion, t1027, execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Invoke-Obfuscation Via Use Clip - PowerShell Module

### Description

Detects Obfuscated Powershell via use Clip.exe in Scripts

```yml
title: Invoke-Obfuscation Via Use Clip - PowerShell Module
id: ebdf49d8-b89c-46c9-8fdf-2c308406f6bd
related:
    - id: db92dd33-a3ad-49cf-8c2c-608c3e30ace0
      type: derived
status: test
description: Detects Obfuscated Powershell via use Clip.exe in Scripts
references:
    - https://github.com/SigmaHQ/sigma/issues/1009  # (Task29)
author: Nikita Nazarov, oscd.community
date: 2020/10/09
modified: 2022/11/29
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
        Payload|re: '(?i).*?echo.*clip.*&&.*(Clipboard|i`?n`?v`?o`?k`?e`?).*'
    condition: selection_4103
falsepositives:
    - Unknown
level: high

```
