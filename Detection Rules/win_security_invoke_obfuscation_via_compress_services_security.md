---
title: "Invoke-Obfuscation COMPRESS OBFUSCATION - Security"
status: "test"
created: "2020/10/18"
last_modified: "2022/11/29"
tags: [defense_evasion, t1027, execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "medium"
---

## Invoke-Obfuscation COMPRESS OBFUSCATION - Security

### Description

Detects Obfuscated Powershell via COMPRESS OBFUSCATION

```yml
title: Invoke-Obfuscation COMPRESS OBFUSCATION - Security
id: 7a922f1b-2635-4d6c-91ef-af228b198ad3
related:
    - id: 175997c5-803c-4b08-8bb0-70b099f47595
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
    service: security
    definition: The 'System Security Extension' audit subcategory need to be enabled to log the EID 4697
detection:
    selection:
        EventID: 4697
        ServiceFileName|contains|all:
            - 'new-object'
            - 'text.encoding]::ascii'
            - 'readtoend'
        ServiceFileName|contains:
            - 'system.io.compression.deflatestream'
            - 'system.io.streamreader'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
