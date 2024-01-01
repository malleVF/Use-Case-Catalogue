---
title: "Pubprn.vbs Proxy Execution"
status: "test"
created: "2022/05/28"
last_modified: ""
tags: [defense_evasion, t1216_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Pubprn.vbs Proxy Execution

### Description

Detects the use of the 'Pubprn.vbs' Microsoft signed script to execute commands.

```yml
title: Pubprn.vbs Proxy Execution
id: 1fb76ab8-fa60-4b01-bddd-71e89bf555da
status: test
description: Detects the use of the 'Pubprn.vbs' Microsoft signed script to execute commands.
references:
    - https://lolbas-project.github.io/lolbas/Scripts/Pubprn/
author: frack113
date: 2022/05/28
tags:
    - attack.defense_evasion
    - attack.t1216.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '\pubprn.vbs'
            - 'script:'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
