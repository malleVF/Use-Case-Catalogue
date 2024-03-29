---
title: "Invoke-Obfuscation Via Use Clip - Security"
status: "test"
created: "2020/10/09"
last_modified: "2022/11/29"
tags: [defense_evasion, t1027, execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## Invoke-Obfuscation Via Use Clip - Security

### Description

Detects Obfuscated Powershell via use Clip.exe in Scripts

```yml
title: Invoke-Obfuscation Via Use Clip - Security
id: 1a0a2ff1-611b-4dac-8216-8a7b47c618a6
related:
    - id: 63e3365d-4824-42d8-8b82-e56810fefa0c
      type: derived
status: test
description: Detects Obfuscated Powershell via use Clip.exe in Scripts
references:
    - https://github.com/SigmaHQ/sigma/issues/1009 # (Task29)
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
        ServiceFileName|contains: '(Clipboard|i'
    condition: selection
falsepositives:
    - Unknown
level: high

```
