---
title: "Invoke-Obfuscation Via Use MSHTA - Security"
status: "test"
created: "2020/10/09"
last_modified: "2022/11/29"
tags: [defense_evasion, t1027, execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## Invoke-Obfuscation Via Use MSHTA - Security

### Description

Detects Obfuscated Powershell via use MSHTA in Scripts

```yml
title: Invoke-Obfuscation Via Use MSHTA - Security
id: 9b8d9203-4e0f-4cd9-bb06-4cc4ea6d0e9a
related:
    - id: 7e9c7999-0f9b-4d4a-a6ed-af6d553d4af4
      type: derived
status: test
description: Detects Obfuscated Powershell via use MSHTA in Scripts
references:
    - https://github.com/SigmaHQ/sigma/issues/1009 # (Task31)
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
    service: security
    definition: The 'System Security Extension' audit subcategory need to be enabled to log the EID 4697
detection:
    selection:
        EventID: 4697
        ServiceFileName|contains|all:
            - 'mshta'
            - 'vbscript:createobject'
            - '.run'
            - 'window.close'
    condition: selection
falsepositives:
    - Unknown
level: high

```
