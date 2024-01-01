---
title: "HackTool - ADCSPwn Execution"
status: "test"
created: "2021/07/31"
last_modified: "2023/02/04"
tags: [credential_access, t1557_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## HackTool - ADCSPwn Execution

### Description

Detects command line parameters used by ADCSPwn, a tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service

```yml
title: HackTool - ADCSPwn Execution
id: cd8c163e-a19b-402e-bdd5-419ff5859f12
status: test
description: Detects command line parameters used by ADCSPwn, a tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
references:
    - https://github.com/bats3c/ADCSPwn
author: Florian Roth (Nextron Systems)
date: 2021/07/31
modified: 2023/02/04
tags:
    - attack.credential_access
    - attack.t1557.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - ' --adcs '
            - ' --port '
    condition: selection
falsepositives:
    - Unlikely
level: high

```
