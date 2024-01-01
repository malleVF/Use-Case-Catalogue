---
title: "Okta API Token Created"
status: "test"
created: "2021/09/12"
last_modified: "2022/10/09"
tags: [persistence, detection_rule]
logsrc_product: "okta"
logsrc_service: "okta"
level: "medium"
---

## Okta API Token Created

### Description

Detects when a API token is created

```yml
title: Okta API Token Created
id: 19951c21-229d-4ccb-8774-b993c3ff3c5c
status: test
description: Detects when a API token is created
references:
    - https://developer.okta.com/docs/reference/api/system-log/
    - https://developer.okta.com/docs/reference/api/event-types/
author: Austin Songer @austinsonger
date: 2021/09/12
modified: 2022/10/09
tags:
    - attack.persistence
logsource:
    product: okta
    service: okta
detection:
    selection:
        eventtype: system.api_token.create
    condition: selection
falsepositives:
    - Legitimate creation of an API token by authorized users
level: medium

```