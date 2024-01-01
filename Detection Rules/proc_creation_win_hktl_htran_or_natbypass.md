---
title: "HackTool - Htran/NATBypass Execution"
status: "test"
created: "2022/12/27"
last_modified: "2023/02/04"
tags: [command_and_control, t1090, s0040, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## HackTool - Htran/NATBypass Execution

### Description

Detects executable names or flags used by Htran or Htran-like tools (e.g. NATBypass)

```yml
title: HackTool - Htran/NATBypass Execution
id: f5e3b62f-e577-4e59-931e-0a15b2b94e1e
status: test
description: Detects executable names or flags used by Htran or Htran-like tools (e.g. NATBypass)
references:
    - https://github.com/HiwinCN/HTran
    - https://github.com/cw1997/NATBypass
author: Florian Roth (Nextron Systems)
date: 2022/12/27
modified: 2023/02/04
tags:
    - attack.command_and_control
    - attack.t1090
    - attack.s0040
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith:
            - '\htran.exe'
            - '\lcx.exe'
    selection_cli:
        CommandLine|contains:
            - '.exe -tran '
            - '.exe -slave '
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: high

```