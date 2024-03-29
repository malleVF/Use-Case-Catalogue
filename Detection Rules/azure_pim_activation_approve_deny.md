---
title: "PIM Approvals And Deny Elevation"
status: "test"
created: "2022/08/09"
last_modified: ""
tags: [privilege_escalation, t1078_004, detection_rule]
logsrc_product: "azure"
logsrc_service: "auditlogs"
level: "high"
---

## PIM Approvals And Deny Elevation

### Description

Detects when a PIM elevation is approved or denied. Outside of normal operations should be investigated.

```yml
title: PIM Approvals And Deny Elevation
id: 039a7469-0296-4450-84c0-f6966b16dc6d
status: test
description: Detects when a PIM elevation is approved or denied. Outside of normal operations should be investigated.
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-privileged-identity-management#azure-ad-roles-assignment
author: Mark Morowczynski '@markmorow', Yochana Henderson, '@Yochana-H'
date: 2022/08/09
tags:
    - attack.privilege_escalation
    - attack.t1078.004
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        properties.message: Request Approved/Denied
    condition: selection
falsepositives:
    - Actual admin using PIM.
level: high

```
