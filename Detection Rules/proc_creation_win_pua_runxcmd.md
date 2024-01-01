---
title: "PUA - RunXCmd Execution"
status: "test"
created: "2022/01/24"
last_modified: "2023/02/14"
tags: [execution, t1569_002, s0029, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## PUA - RunXCmd Execution

### Description

Detects the use of the RunXCmd tool to execute commands with System or TrustedInstaller accounts

```yml
title: PUA - RunXCmd Execution
id: 93199800-b52a-4dec-b762-75212c196542
status: test
description: Detects the use of the RunXCmd tool to execute commands with System or TrustedInstaller accounts
references:
    - https://www.d7xtech.com/free-software/runx/
    - https://www.winhelponline.com/blog/run-program-as-system-localsystem-account-windows/
author: Florian Roth (Nextron Systems)
date: 2022/01/24
modified: 2023/02/14
tags:
    - attack.execution
    - attack.t1569.002
    - attack.s0029
logsource:
    category: process_creation
    product: windows
detection:
    selection_account:
        CommandLine|contains:
            - ' /account=system '
            - ' /account=ti '
    selection_exec:
        CommandLine|contains: '/exec='
    condition: all of selection_*
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Legitimate use by administrators
level: high

```
