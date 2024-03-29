---
title: "Invoke-Obfuscation Via Use Rundll32 - Security"
status: "test"
created: "2020/10/09"
last_modified: "2022/11/29"
tags: [defense_evasion, t1027, execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## Invoke-Obfuscation Via Use Rundll32 - Security

### Description

Detects Obfuscated Powershell via use Rundll32 in Scripts

```yml
title: Invoke-Obfuscation Via Use Rundll32 - Security
id: cd0f7229-d16f-42de-8fe3-fba365fbcb3a
related:
    - id: 641a4bfb-c017-44f7-800c-2aee0184ce9b
      type: derived
status: test
description: Detects Obfuscated Powershell via use Rundll32 in Scripts
references:
    - https://github.com/SigmaHQ/sigma/issues/1009 # (Task30)
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
            - '&&'
            - 'rundll32'
            - 'shell32.dll'
            - 'shellexec_rundll'
        ServiceFileName|contains:
            - value
            - invoke
            - comspec
            - iex
    condition: selection
falsepositives:
    - Unknown
level: high

```
