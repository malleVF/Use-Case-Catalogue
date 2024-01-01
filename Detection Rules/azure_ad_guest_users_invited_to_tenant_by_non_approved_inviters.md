---
title: "Guest Users Invited To Tenant By Non Approved Inviters"
status: "test"
created: "2022/07/28"
last_modified: ""
tags: [initial_access, t1078, detection_rule]
logsrc_product: "azure"
logsrc_service: "auditlogs"
level: "medium"
---

## Guest Users Invited To Tenant By Non Approved Inviters

### Description

Detects guest users being invited to tenant by non-approved inviters

```yml
title: Guest Users Invited To Tenant By Non Approved Inviters
id: 4ad97bf5-a514-41a4-abd3-4f3455ad4865
status: test
description: Detects guest users being invited to tenant by non-approved inviters
references:
    - https://docs.microsoft.com/en-gb/azure/active-directory/fundamentals/security-operations-user-accounts#monitoring-external-user-sign-ins
author: MikeDuddington, '@dudders1'
date: 2022/07/28
tags:
    - attack.initial_access
    - attack.t1078
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        Category: 'UserManagement'
        OperationName: 'Invite external user'
    filter:
        InitiatedBy|contains: '<approved guest inviter use OR for multiple>'
    condition: selection and not filter
falsepositives:
    - If this was approved by System Administrator.
level: medium

```