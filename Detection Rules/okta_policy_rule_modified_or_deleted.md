---
title: "Okta Policy Rule Modified or Deleted"
status: "test"
created: "2021/09/12"
last_modified: "2022/10/09"
tags: [impact, detection_rule]
logsrc_product: "okta"
logsrc_service: "okta"
level: "medium"
---

## Okta Policy Rule Modified or Deleted

### Description

Detects when an Policy Rule is Modified or Deleted.

```yml
title: Okta Policy Rule Modified or Deleted
id: 0c97c1d3-4057-45c9-b148-1de94b631931
status: test
description: Detects when an Policy Rule is Modified or Deleted.
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
            - policy.rule.update
            - policy.rule.delete
    condition: selection
falsepositives:
    - Unknown

level: medium

```
