---
title: "Invoke-Obfuscation COMPRESS OBFUSCATION - PowerShell Module"
status: "test"
created: "2020/10/18"
last_modified: "2022/11/29"
tags: [defense_evasion, t1027, execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Invoke-Obfuscation COMPRESS OBFUSCATION - PowerShell Module

### Description

Detects Obfuscated Powershell via COMPRESS OBFUSCATION

```yml
title: Invoke-Obfuscation COMPRESS OBFUSCATION - PowerShell Module
id: 7034cbbb-cc55-4dc2-8dad-36c0b942e8f1
related:
    - id: 20e5497e-331c-4cd5-8d36-935f6e2a9a07
      type: derived
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
    category: ps_module
    definition: 0ad03ef1-f21b-4a79-8ce8-e6900c54b65b
detection:
    selection_4103:
        Payload|contains|all:
            - 'new-object'
            - 'text.encoding]::ascii'
        Payload|contains:
            - 'system.io.compression.deflatestream'
            - 'system.io.streamreader'
        Payload|endswith: 'readtoend'
    condition: selection_4103
falsepositives:
    - Unknown
level: medium

```
