---
title: "PowerShell Called from an Executable Version Mismatch"
status: "test"
created: "2017/03/05"
last_modified: "2023/10/27"
tags: [defense_evasion, execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## PowerShell Called from an Executable Version Mismatch

### Description

Detects PowerShell called from an executable by the version mismatch method

```yml
title: PowerShell Called from an Executable Version Mismatch
id: c70e019b-1479-4b65-b0cc-cd0c6093a599
status: test
description: Detects PowerShell called from an executable by the version mismatch method
references:
    - https://adsecurity.org/?p=2921
author: Sean Metcalf (source), Florian Roth (Nextron Systems)
date: 2017/03/05
modified: 2023/10/27
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: ps_classic_start
detection:
    selection_engine:
        Data|contains:
            - 'EngineVersion=2.'
            - 'EngineVersion=4.'
            - 'EngineVersion=5.'
    selection_host:
        Data|contains: 'HostVersion=3.'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high

```
