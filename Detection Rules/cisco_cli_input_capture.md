---
title: "Cisco Show Commands Input"
status: "test"
created: "2019/08/11"
last_modified: "2023/01/04"
tags: [credential_access, t1552_003, detection_rule]
logsrc_product: "cisco"
logsrc_service: "aaa"
level: "medium"
---

## Cisco Show Commands Input

### Description

See what commands are being input into the device by other people, full credentials can be in the history

```yml
title: Cisco Show Commands Input
id: b094d9fb-b1ad-4650-9f1a-fb7be9f1d34b
status: test
description: See what commands are being input into the device by other people, full credentials can be in the history
author: Austin Clark
date: 2019/08/11
modified: 2023/01/04
tags:
    - attack.credential_access
    - attack.t1552.003
logsource:
    product: cisco
    service: aaa
detection:
    keywords:
        - 'show history'
        - 'show history all'
        - 'show logging'
    condition: keywords
fields:
    - CmdSet
falsepositives:
    - Not commonly run by administrators, especially if remote logging is configured
level: medium

```