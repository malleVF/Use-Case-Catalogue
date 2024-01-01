---
title: "Okta Application Sign-On Policy Modified or Deleted"
status: "test"
created: "2021/09/12"
last_modified: "2022/10/09"
tags: [impact, detection_rule]
logsrc_product: "okta"
logsrc_service: "okta"
level: "medium"
---

## Okta Application Sign-On Policy Modified or Deleted

### Description

Detects when an application Sign-on Policy is modified or deleted.

```yml
title: Okta Application Sign-On Policy Modified or Deleted
id: 8f668cc4-c18e-45fe-ad00-624a981cf88a
status: test
description: Detects when an application Sign-on Policy is modified or deleted.
references:
    - https://developer.okta.com/docs/reference/api/system-log/
    - https://developer.okta.com/docs/reference/api/event-types/
author: Austin Songer @austinsonger
date: 2021/09/12
modified: 2022/10/09
tags:
    - attack.impact
logsource:
    product: okta
    service: okta
detection:
    selection:
        eventtype:
            - application.policy.sign_on.update
            - application.policy.sign_on.rule.delete
    condition: selection
falsepositives:
    - Unknown
level: medium

```
