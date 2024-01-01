---
title: "Bulk Deletion Changes To Privileged Account Permissions"
status: "test"
created: "2022/08/05"
last_modified: ""
tags: [persistence, t1098, detection_rule]
logsrc_product: "azure"
logsrc_service: "auditlogs"
level: "high"
---

## Bulk Deletion Changes To Privileged Account Permissions

### Description

Detects when a user is removed from a privileged role. Bulk changes should be investigated.

```yml
title: Bulk Deletion Changes To Privileged Account Permissions
id: 102e11e3-2db5-4c9e-bc26-357d42585d21
status: test
description: Detects when a user is removed from a privileged role. Bulk changes should be investigated.
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-privileged-identity-management#azure-ad-roles-assignment
author: Mark Morowczynski '@markmorow', Yochana Henderson, '@Yochana-H'
date: 2022/08/05
tags:
    - attack.persistence
    - attack.t1098
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        properties.message:
            - Remove eligible member (permanent)
            - Remove eligible member (eligible)
    condition: selection
falsepositives:
    - Legtimate administrator actions of removing members from a role
level: high

```
