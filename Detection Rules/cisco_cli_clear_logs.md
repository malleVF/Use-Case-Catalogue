---
title: "Cisco Clear Logs"
status: "test"
created: "2019/08/12"
last_modified: "2023/05/26"
tags: [defense_evasion, t1070_003, detection_rule]
logsrc_product: "cisco"
logsrc_service: "aaa"
level: "high"
---

## Cisco Clear Logs

### Description

Clear command history in network OS which is used for defense evasion

```yml
title: Cisco Clear Logs
id: ceb407f6-8277-439b-951f-e4210e3ed956
status: test
description: Clear command history in network OS which is used for defense evasion
author: Austin Clark
date: 2019/08/12
modified: 2023/05/26
tags:
    - attack.defense_evasion
    - attack.t1070.003
logsource:
    product: cisco
    service: aaa
detection:
    keywords:
        - 'clear logging'
        - 'clear archive'
    condition: keywords
fields:
    - src
    - CmdSet
    - User
    - Privilege_Level
    - Remote_Address
falsepositives:
    - Legitimate administrators may run these commands
level: high

```
