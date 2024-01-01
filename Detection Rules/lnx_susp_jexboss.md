---
title: "JexBoss Command Sequence"
status: "test"
created: "2017/08/24"
last_modified: "2022/07/07"
tags: [execution, t1059_004, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "high"
---

## JexBoss Command Sequence

### Description

Detects suspicious command sequence that JexBoss

```yml
title: JexBoss Command Sequence
id: 8ec2c8b4-557a-4121-b87c-5dfb3a602fae
status: test
description: Detects suspicious command sequence that JexBoss
references:
    - https://www.us-cert.gov/ncas/analysis-reports/AR18-312A
author: Florian Roth (Nextron Systems)
date: 2017/08/24
modified: 2022/07/07
tags:
    - attack.execution
    - attack.t1059.004
logsource:
    product: linux
detection:
    selection1:
        - 'bash -c /bin/bash'
    selection2:
        - '&/dev/tcp/'
    condition: all of selection*
falsepositives:
    - Unknown
level: high

```
