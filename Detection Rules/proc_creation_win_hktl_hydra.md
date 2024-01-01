---
title: "HackTool - Hydra Password Bruteforce Execution"
status: "test"
created: "2020/10/05"
last_modified: "2023/02/04"
tags: [credential_access, t1110, t1110_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## HackTool - Hydra Password Bruteforce Execution

### Description

Detects command line parameters used by Hydra password guessing hack tool

```yml
title: HackTool - Hydra Password Bruteforce Execution
id: aaafa146-074c-11eb-adc1-0242ac120002
status: test
description: Detects command line parameters used by Hydra password guessing hack tool
references:
    - https://github.com/vanhauser-thc/thc-hydra
author: Vasiliy Burov
date: 2020/10/05
modified: 2023/02/04
tags:
    - attack.credential_access
    - attack.t1110
    - attack.t1110.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '-u '
            - '-p '
        CommandLine|contains:
            - '^USER^'
            - '^PASS^'
    condition: selection
falsepositives:
    - Software that uses the caret encased keywords PASS and USER in its command line
level: high

```