---
title: "Invoke-Obfuscation Via Stdin"
status: "test"
created: "2020/10/12"
last_modified: "2022/11/16"
tags: [defense_evasion, t1027, execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Invoke-Obfuscation Via Stdin

### Description

Detects Obfuscated Powershell via Stdin in Scripts

```yml
title: Invoke-Obfuscation Via Stdin
id: 9c14c9fa-1a63-4a64-8e57-d19280559490
status: test
description: Detects Obfuscated Powershell via Stdin in Scripts
references:
    - https://github.com/SigmaHQ/sigma/issues/1009 # (Task28)
author: Nikita Nazarov, oscd.community
date: 2020/10/12
modified: 2022/11/16
tags:
    - attack.defense_evasion
    - attack.t1027
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        # CommandLine|re: '(?i).*(set).*&&\s?set.*(environment|invoke|\${?input).*&&.*"'
        CommandLine|contains|all:
            - 'set'
            - '&&'
        CommandLine|contains:
            - 'environment'
            - 'invoke'
            - 'input'
    condition: selection
falsepositives:
    - Unknown
level: high

```
