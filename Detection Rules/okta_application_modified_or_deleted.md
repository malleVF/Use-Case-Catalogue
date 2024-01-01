---
title: "Okta Application Modified or Deleted"
status: "test"
created: "2021/09/12"
last_modified: "2022/10/09"
tags: [impact, detection_rule]
logsrc_product: "okta"
logsrc_service: "okta"
level: "medium"
---

## Okta Application Modified or Deleted

### Description

Detects when an application is modified or deleted.

```yml
title: Okta Application Modified or Deleted
id: 7899144b-e416-4c28-b0b5-ab8f9e0a541d
status: test
description: Detects when an application is modified or deleted.
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
            - application.lifecycle.update
            - application.lifecycle.delete
    condition: selection
falsepositives:
    - Unknown

level: medium

```
