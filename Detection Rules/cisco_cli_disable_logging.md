---
title: "Cisco Disabling Logging"
status: "test"
created: "2019/08/11"
last_modified: "2023/01/04"
tags: [defense_evasion, t1562_001, detection_rule]
logsrc_product: "cisco"
logsrc_service: "aaa"
level: "high"
---

## Cisco Disabling Logging

### Description

Turn off logging locally or remote

```yml
title: Cisco Disabling Logging
id: 9e8f6035-88bf-4a63-96b6-b17c0508257e
status: test
description: Turn off logging locally or remote
author: Austin Clark
date: 2019/08/11
modified: 2023/01/04
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    product: cisco
    service: aaa
detection:
    keywords:
        - 'no logging'
        - 'no aaa new-model'
    condition: keywords
fields:
    - src
    - CmdSet
    - User
    - Privilege_Level
    - Remote_Address
falsepositives:
    - Unknown
level: high

```
