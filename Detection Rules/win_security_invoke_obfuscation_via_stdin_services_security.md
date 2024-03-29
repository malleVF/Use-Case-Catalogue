---
title: "Invoke-Obfuscation Via Stdin - Security"
status: "test"
created: "2020/10/12"
last_modified: "2022/11/29"
tags: [defense_evasion, t1027, execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## Invoke-Obfuscation Via Stdin - Security

### Description

Detects Obfuscated Powershell via Stdin in Scripts

```yml
title: Invoke-Obfuscation Via Stdin - Security
id: 80b708f3-d034-40e4-a6c8-d23b7a7db3d1
related:
    - id: 487c7524-f892-4054-b263-8a0ace63fc25
      type: derived
status: test
description: Detects Obfuscated Powershell via Stdin in Scripts
references:
    - https://github.com/SigmaHQ/sigma/issues/1009 # (Task28)
author: Nikita Nazarov, oscd.community
date: 2020/10/12
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
            - 'set'
            - '&&'
        ServiceFileName|contains:
            - 'environment'
            - 'invoke'
            - '${input)'
    condition: selection
falsepositives:
    - Unknown
level: high

```
