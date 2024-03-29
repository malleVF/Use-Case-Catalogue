---
title: "Indirect Inline Command Execution Via Bash.EXE"
status: "experimental"
created: "2021/11/24"
last_modified: "2023/08/15"
tags: [defense_evasion, t1202, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Indirect Inline Command Execution Via Bash.EXE

### Description

Detects execution of Microsoft bash launcher with the "-c" flag. This can be used to potentially bypass defenses and execute Linux or Windows-based binaries directly via bash

```yml
title: Indirect Inline Command Execution Via Bash.EXE
id: 5edc2273-c26f-406c-83f3-f4d948e740dd
status: experimental
description: Detects execution of Microsoft bash launcher with the "-c" flag. This can be used to potentially bypass defenses and execute Linux or Windows-based binaries directly via bash
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Bash/
author: frack113
date: 2021/11/24
modified: 2023/08/15
tags:
    - attack.defense_evasion
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - ':\Windows\System32\bash.exe'
              - ':\Windows\SysWOW64\bash.exe'
        - OriginalFileName: 'Bash.exe'
    selection_cli:
        CommandLine|contains: ' -c '
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium

```
