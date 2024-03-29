---
title: "User State Changed From Guest To Member"
status: "test"
created: "2022/06/30"
last_modified: ""
tags: [privilege_escalation, initial_access, t1078_004, detection_rule]
logsrc_product: "azure"
logsrc_service: "auditlogs"
level: "medium"
---

## User State Changed From Guest To Member

### Description

Detects the change of user type from "Guest" to "Member" for potential elevation of privilege.

```yml
title: User State Changed From Guest To Member
id: 8dee7a0d-43fd-4b3c-8cd1-605e189d195e
status: test
description: Detects the change of user type from "Guest" to "Member" for potential elevation of privilege.
references:
    - https://docs.microsoft.com/en-gb/azure/active-directory/fundamentals/security-operations-user-accounts#monitoring-external-user-sign-ins
author: MikeDuddington, '@dudders1'
date: 2022/06/30
tags:
    - attack.privilege_escalation
    - attack.initial_access
    - attack.t1078.004
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        Category: 'UserManagement'
        OperationName: 'Update user'
        properties.message: '"displayName":"UserType","oldValue":"[\"Guest\"]","newValue":"[\"Member\"]"'
    condition: selection
falsepositives:
    - If this was approved by System Administrator.
level: medium

```
