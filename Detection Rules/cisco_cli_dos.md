---
title: "Cisco Denial of Service"
status: "test"
created: "2019/08/15"
last_modified: "2023/01/04"
tags: [impact, t1495, t1529, t1565_001, detection_rule]
logsrc_product: "cisco"
logsrc_service: "aaa"
level: "medium"
---

## Cisco Denial of Service

### Description

Detect a system being shutdown or put into different boot mode

```yml
title: Cisco Denial of Service
id: d94a35f0-7a29-45f6-90a0-80df6159967c
status: test
description: Detect a system being shutdown or put into different boot mode
author: Austin Clark
date: 2019/08/15
modified: 2023/01/04
tags:
    - attack.impact
    - attack.t1495
    - attack.t1529
    - attack.t1565.001
logsource:
    product: cisco
    service: aaa
detection:
    keywords:
        - 'shutdown'
        - 'config-register 0x2100'
        - 'config-register 0x2142'
    condition: keywords
fields:
    - CmdSet
falsepositives:
    - Legitimate administrators may run these commands, though rarely.
level: medium

```
