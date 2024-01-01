---
title: "User Added To Privilege Role"
status: "test"
created: "2022/08/06"
last_modified: ""
tags: [privilege_escalation, defense_evasion, t1078_004, detection_rule]
logsrc_product: "azure"
logsrc_service: "auditlogs"
level: "high"
---

## User Added To Privilege Role

### Description

Detects when a user is added to a privileged role.

```yml
title: User Added To Privilege Role
id: 49a268a4-72f4-4e38-8a7b-885be690c5b5
status: test
description: Detects when a user is added to a privileged role.
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-privileged-identity-management#azure-ad-roles-assignment
author: Mark Morowczynski '@markmorow', Yochana Henderson, '@Yochana-H'
date: 2022/08/06
tags:
    - attack.privilege_escalation
    - attack.defense_evasion
    - attack.t1078.004
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        properties.message:
            - Add eligible member (permanent)
            - Add eligible member (eligible)
    condition: selection
falsepositives:
    - Legtimate administrator actions of adding members from a role
level: high

```
