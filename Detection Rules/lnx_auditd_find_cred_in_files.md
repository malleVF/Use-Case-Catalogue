---
title: "Credentials In Files - Linux"
status: "test"
created: "2020/10/15"
last_modified: "2023/04/30"
tags: [credential_access, t1552_001, detection_rule]
logsrc_product: "linux"
logsrc_service: "auditd"
level: "high"
---

## Credentials In Files - Linux

### Description

Detecting attempts to extract passwords with grep

```yml
title: Credentials In Files - Linux
id: df3fcaea-2715-4214-99c5-0056ea59eb35
status: test
description: 'Detecting attempts to extract passwords with grep'
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1552.001/T1552.001.md
author: 'Igor Fits, oscd.community'
date: 2020/10/15
modified: 2023/04/30
tags:
    - attack.credential_access
    - attack.t1552.001
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: 'EXECVE'
    keywords:
        '|all':
            - 'grep'
            - 'password'
    condition: selection and keywords
falsepositives:
    - Unknown
level: high

```
