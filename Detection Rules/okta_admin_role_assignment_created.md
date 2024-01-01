---
title: "Okta Admin Role Assignment Created"
status: "test"
created: "2023/01/19"
last_modified: ""
tags: [persistence, detection_rule]
logsrc_product: "okta"
logsrc_service: "okta"
level: "medium"
---

## Okta Admin Role Assignment Created

### Description

Detects when a new admin role assignment is created. Which could be a sign of privilege escalation or persistence

```yml
title: Okta Admin Role Assignment Created
id: 139bdd4b-9cd7-49ba-a2f4-744d0a8f5d8c
status: test
description: Detects when a new admin role assignment is created. Which could be a sign of privilege escalation or persistence
references:
    - https://developer.okta.com/docs/reference/api/system-log/
    - https://developer.okta.com/docs/reference/api/event-types/
author: Nikita Khalimonenkov
date: 2023/01/19
tags:
    - attack.persistence
logsource:
    product: okta
    service: okta
detection:
    selection:
        eventtype: 'iam.resourceset.bindings.add'
    condition: selection
falsepositives:
    - Legitimate creation of a new admin role assignment
level: medium

```
