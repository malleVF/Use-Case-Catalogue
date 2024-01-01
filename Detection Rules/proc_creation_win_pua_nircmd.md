---
title: "PUA - NirCmd Execution"
status: "experimental"
created: "2022/01/24"
last_modified: "2023/02/13"
tags: [execution, t1569_002, s0029, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## PUA - NirCmd Execution

### Description

Detects the use of NirCmd tool for command execution, which could be the result of legitimate administrative activity

```yml
title: PUA - NirCmd Execution
id: 4e2ed651-1906-4a59-a78a-18220fca1b22
status: experimental
description: Detects the use of NirCmd tool for command execution, which could be the result of legitimate administrative activity
references:
    - https://www.nirsoft.net/utils/nircmd.html
    - https://www.winhelponline.com/blog/run-program-as-system-localsystem-account-windows/
    - https://www.nirsoft.net/utils/nircmd2.html#using
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2022/01/24
modified: 2023/02/13
tags:
    - attack.execution
    - attack.t1569.002
    - attack.s0029
logsource:
    category: process_creation
    product: windows
detection:
    selection_org:
        - Image|endswith: '\NirCmd.exe'
        - OriginalFileName: 'NirCmd.exe'
    selection_cmd:
        CommandLine|contains:
            - ' execmd '
            - '.exe script '
            - '.exe shexec '
            - ' runinteractive '
    combo_exec:
        CommandLine|contains:
            - ' exec '
            - ' exec2 '
    combo_exec_params:
        CommandLine|contains:
            - ' show '
            - ' hide '
    condition: 1 of selection_* or all of combo_*
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Legitimate use by administrators
level: medium

```
