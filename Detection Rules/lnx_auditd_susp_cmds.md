---
title: "Suspicious Commands Linux"
status: "test"
created: "2017/12/12"
last_modified: "2022/10/05"
tags: [execution, t1059_004, detection_rule]
logsrc_product: "linux"
logsrc_service: "auditd"
level: "medium"
---

## Suspicious Commands Linux

### Description

Detects relevant commands often related to malware or hacking activity

```yml
title: Suspicious Commands Linux
id: 1543ae20-cbdf-4ec1-8d12-7664d667a825
status: test
description: Detects relevant commands often related to malware or hacking activity
references:
    - Internal Research - mostly derived from exploit code including code in MSF
author: Florian Roth (Nextron Systems)
date: 2017/12/12
modified: 2022/10/05
tags:
    - attack.execution
    - attack.t1059.004
logsource:
    product: linux
    service: auditd
detection:
    cmd1:
        type: 'EXECVE'
        a0: 'chmod'
        a1: 777
    cmd2:
        type: 'EXECVE'
        a0: 'chmod'
        a1: 'u+s'
    cmd3:
        type: 'EXECVE'
        a0: 'cp'
        a1: '/bin/ksh'
    cmd4:
        type: 'EXECVE'
        a0: 'cp'
        a1: '/bin/sh'
    condition: 1 of cmd*
falsepositives:
    - Admin activity
level: medium

```
