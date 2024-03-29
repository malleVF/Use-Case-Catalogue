---
title: "Okta MFA Reset or Deactivated"
status: "test"
created: "2021/09/21"
last_modified: "2022/10/09"
tags: [persistence, credential_access, defense_evasion, t1556_006, detection_rule]
logsrc_product: "okta"
logsrc_service: "okta"
level: "medium"
---

## Okta MFA Reset or Deactivated

### Description

Detects when an attempt at deactivating  or resetting MFA.

```yml
title: Okta MFA Reset or Deactivated
id: 50e068d7-1e6b-4054-87e5-0a592c40c7e0
status: test
description: Detects when an attempt at deactivating  or resetting MFA.
references:
    - https://developer.okta.com/docs/reference/api/system-log/
    - https://developer.okta.com/docs/reference/api/event-types/
author: Austin Songer @austinsonger
date: 2021/09/21
modified: 2022/10/09
tags:
    - attack.persistence
    - attack.credential_access
    - attack.defense_evasion
    - attack.t1556.006
logsource:
    product: okta
    service: okta
detection:
    selection:
        eventtype:
            - user.mfa.factor.deactivate
            - user.mfa.factor.reset_all
    condition: selection
falsepositives:
    - If a MFA reset or deactivated was performed by a system administrator.
level: medium

```
