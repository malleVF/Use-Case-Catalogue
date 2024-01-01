---
title: "Suspicious Windows Update Agent Empty Cmdline"
status: "test"
created: "2022/02/26"
last_modified: "2023/11/11"
tags: [defense_evasion, t1036, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious Windows Update Agent Empty Cmdline

### Description

Detects suspicious Windows Update Agent activity in which a wuauclt.exe process command line doesn't contain any command line flags


```yml
title: Suspicious Windows Update Agent Empty Cmdline
id: 52d097e2-063e-4c9c-8fbb-855c8948d135
status: test
description: |
    Detects suspicious Windows Update Agent activity in which a wuauclt.exe process command line doesn't contain any command line flags
references:
    - https://redcanary.com/blog/blackbyte-ransomware/
author: Florian Roth (Nextron Systems)
date: 2022/02/26
modified: 2023/11/11
tags:
    - attack.defense_evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\Wuauclt.exe'
        - OriginalFileName: 'Wuauclt.exe'
    selection_cli:
        CommandLine|endswith:
            - 'Wuauclt'
            - 'Wuauclt.exe'
    condition: all of selection*
falsepositives:
    - Unknown
level: high

```
