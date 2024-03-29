---
title: "App Role Added"
status: "test"
created: "2022/07/19"
last_modified: ""
tags: [persistence, privilege_escalation, t1098_003, detection_rule]
logsrc_product: "azure"
logsrc_service: "auditlogs"
level: "medium"
---

## App Role Added

### Description

Detects when an app is assigned Azure AD roles, such as global administrator, or Azure RBAC roles, such as subscription owner.

```yml
title: App Role Added
id: b04934b2-0a68-4845-8a19-bdfed3a68a7a
status: test
description: Detects when an app is assigned Azure AD roles, such as global administrator, or Azure RBAC roles, such as subscription owner.
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-applications#service-principal-assigned-to-a-role
author: Bailey Bercik '@baileybercik', Mark Morowczynski '@markmorow'
date: 2022/07/19
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1098.003
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        properties.message:
            - Add member to role
            - Add eligible member to role
            - Add scoped member to role
    condition: selection
falsepositives:
    - When the permission is legitimately needed for the app
level: medium

```
