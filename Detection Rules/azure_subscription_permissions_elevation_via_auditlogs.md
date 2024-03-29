---
title: "Azure Subscription Permission Elevation Via AuditLogs"
status: "test"
created: "2021/11/26"
last_modified: "2022/12/25"
tags: [initial_access, t1078, detection_rule]
logsrc_product: "azure"
logsrc_service: "auditlogs"
level: "high"
---

## Azure Subscription Permission Elevation Via AuditLogs

### Description

Detects when a user has been elevated to manage all Azure Subscriptions.
This change should be investigated immediately if it isn't planned.
This setting could allow an attacker access to Azure subscriptions in your environment.


```yml
title: Azure Subscription Permission Elevation Via AuditLogs
id: ca9bf243-465e-494a-9e54-bf9fc239057d
status: test
description: |
    Detects when a user has been elevated to manage all Azure Subscriptions.
    This change should be investigated immediately if it isn't planned.
    This setting could allow an attacker access to Azure subscriptions in your environment.
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-privileged-accounts#assignment-and-elevation
author: Austin Songer @austinsonger
date: 2021/11/26
modified: 2022/12/25
tags:
    - attack.initial_access
    - attack.t1078
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        Category: 'Administrative'
        OperationName: 'Assigns the caller to user access admin'
    condition: selection
falsepositives:
    - If this was approved by System Administrator.
level: high

```
