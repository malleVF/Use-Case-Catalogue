---
title: "Okta User Account Locked Out"
status: "test"
created: "2021/09/12"
last_modified: "2022/10/09"
tags: [impact, t1531, detection_rule]
logsrc_product: "okta"
logsrc_service: "okta"
level: "medium"
---

## Okta User Account Locked Out

### Description

Detects when an user account is locked out.

```yml
title: Okta User Account Locked Out
id: 14701da0-4b0f-4ee6-9c95-2ffb4e73bb9a
status: test
description: Detects when an user account is locked out.
references:
    - https://developer.okta.com/docs/reference/api/system-log/
    - https://developer.okta.com/docs/reference/api/event-types/
author: Austin Songer @austinsonger
date: 2021/09/12
modified: 2022/10/09
tags:
    - attack.impact
    - attack.t1531
logsource:
    product: okta
    service: okta
detection:
    selection:
        displaymessage: Max sign in attempts exceeded
    condition: selection
falsepositives:
    - Unknown
level: medium

```
