---
title: "Privileged Account Creation"
status: "test"
created: "2022/08/11"
last_modified: "2022/08/16"
tags: [persistence, privilege_escalation, t1078_004, detection_rule]
logsrc_product: "azure"
logsrc_service: "auditlogs"
level: "medium"
---

## Privileged Account Creation

### Description

Detects when a new admin is created.

```yml
title: Privileged Account Creation
id: f7b5b004-dece-46e4-a4a5-f6fd0e1c6947
status: test
description: Detects when a new admin is created.
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-privileged-accounts#changes-to-privileged-accounts
author: Mark Morowczynski '@markmorow', Yochana Henderson, '@Yochana-H', Tim Shelton
date: 2022/08/11
modified: 2022/08/16
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1078.004
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        properties.message|contains|all:
            - Add user
            - Add member to role
        Status: Success
    condition: selection
falsepositives:
    - A legitimate new admin account being created
level: medium

```
