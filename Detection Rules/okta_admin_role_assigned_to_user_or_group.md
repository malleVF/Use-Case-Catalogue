---
title: "Okta Admin Role Assigned to an User or Group"
status: "test"
created: "2021/09/12"
last_modified: "2022/10/09"
tags: [persistence, t1098_003, detection_rule]
logsrc_product: "okta"
logsrc_service: "okta"
level: "medium"
---

## Okta Admin Role Assigned to an User or Group

### Description

Detects when an the Administrator role is assigned to an user or group.

```yml
title: Okta Admin Role Assigned to an User or Group
id: 413d4a81-6c98-4479-9863-014785fd579c
status: test
description: Detects when an the Administrator role is assigned to an user or group.
references:
    - https://developer.okta.com/docs/reference/api/system-log/
    - https://developer.okta.com/docs/reference/api/event-types/
author: Austin Songer @austinsonger
date: 2021/09/12
modified: 2022/10/09
tags:
    - attack.persistence
    - attack.t1098.003
logsource:
    product: okta
    service: okta
detection:
    selection:
        eventtype:
            - group.privilege.grant
            - user.account.privilege.grant
    condition: selection
falsepositives:
    - Administrator roles could be assigned to users or group by other admin users.

level: medium

```
