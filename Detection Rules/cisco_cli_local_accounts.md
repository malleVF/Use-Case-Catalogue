---
title: "Cisco Local Accounts"
status: "test"
created: "2019/08/12"
last_modified: "2023/01/04"
tags: [persistence, t1136_001, t1098, detection_rule]
logsrc_product: "cisco"
logsrc_service: "aaa"
level: "high"
---

## Cisco Local Accounts

### Description

Find local accounts being created or modified as well as remote authentication configurations

```yml
title: Cisco Local Accounts
id: 6d844f0f-1c18-41af-8f19-33e7654edfc3
status: test
description: Find local accounts being created or modified as well as remote authentication configurations
author: Austin Clark
date: 2019/08/12
modified: 2023/01/04
tags:
    - attack.persistence
    - attack.t1136.001
    - attack.t1098
logsource:
    product: cisco
    service: aaa
detection:
    keywords:
        - 'username'
        - 'aaa'
    condition: keywords
fields:
    - CmdSet
falsepositives:
    - When remote authentication is in place, this should not change often
level: high

```
