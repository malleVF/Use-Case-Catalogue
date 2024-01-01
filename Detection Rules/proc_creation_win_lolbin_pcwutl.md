---
title: "Code Execution via Pcwutl.dll"
status: "test"
created: "2020/10/05"
last_modified: "2023/02/09"
tags: [defense_evasion, t1218_011, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Code Execution via Pcwutl.dll

### Description

Detects launch of executable by calling the LaunchApplication function from pcwutl.dll library.

```yml
title: Code Execution via Pcwutl.dll
id: 9386d78a-7207-4048-9c9f-a93a7c2d1c05
status: test
description: Detects launch of executable by calling the LaunchApplication function from pcwutl.dll library.
references:
    - https://lolbas-project.github.io/lolbas/Libraries/Pcwutl/
    - https://twitter.com/harr0ey/status/989617817849876488
author: Julia Fomina, oscd.community
date: 2020/10/05
modified: 2023/02/09
tags:
    - attack.defense_evasion
    - attack.t1218.011
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\rundll32.exe'
        - OriginalFileName: 'RUNDLL32.EXE'
    selection_cli:
        CommandLine|contains|all:
            - 'pcwutl'
            - 'LaunchApplication'
    condition: all of selection_*
falsepositives:
    - Use of Program Compatibility Troubleshooter Helper
level: medium

```
