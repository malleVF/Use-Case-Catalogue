---
title: "Auditing Configuration Changes on Linux Host"
status: "test"
created: "2019/10/25"
last_modified: "2021/11/27"
tags: [defense_evasion, t1562_006, detection_rule]
logsrc_product: "linux"
logsrc_service: "auditd"
level: "high"
---

## Auditing Configuration Changes on Linux Host

### Description

Detect changes in auditd configuration files

```yml
title: Auditing Configuration Changes on Linux Host
id: 977ef627-4539-4875-adf4-ed8f780c4922
status: test
description: Detect changes in auditd configuration files
references:
    - https://github.com/Neo23x0/auditd/blob/master/audit.rules
    - Self Experience
author: Mikhail Larin, oscd.community
date: 2019/10/25
modified: 2021/11/27
tags:
    - attack.defense_evasion
    - attack.t1562.006
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: PATH
        name:
            - /etc/audit/*
            - /etc/libaudit.conf
            - /etc/audisp/*
    condition: selection
fields:
    - exe
    - comm
    - key
falsepositives:
    - Legitimate administrative activity
level: high

```
