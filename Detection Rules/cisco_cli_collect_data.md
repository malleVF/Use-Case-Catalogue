---
title: "Cisco Collect Data"
status: "test"
created: "2019/08/11"
last_modified: "2023/01/04"
tags: [discovery, credential_access, collection, t1087_001, t1552_001, t1005, detection_rule]
logsrc_product: "cisco"
logsrc_service: "aaa"
level: "low"
---

## Cisco Collect Data

### Description

Collect pertinent data from the configuration files

```yml
title: Cisco Collect Data
id: cd072b25-a418-4f98-8ebc-5093fb38fe1a
status: test
description: Collect pertinent data from the configuration files
author: Austin Clark
date: 2019/08/11
modified: 2023/01/04
tags:
    - attack.discovery
    - attack.credential_access
    - attack.collection
    - attack.t1087.001
    - attack.t1552.001
    - attack.t1005
logsource:
    product: cisco
    service: aaa
detection:
    keywords:
        - 'show running-config'
        - 'show startup-config'
        - 'show archive config'
        - 'more'
    condition: keywords
fields:
    - src
    - CmdSet
    - User
    - Privilege_Level
    - Remote_Address
falsepositives:
    - Commonly run by administrators
level: low

```
