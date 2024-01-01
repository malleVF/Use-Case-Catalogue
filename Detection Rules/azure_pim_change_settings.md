---
title: "Changes To PIM Settings"
status: "test"
created: "2022/08/09"
last_modified: ""
tags: [privilege_escalation, persistence, t1078_004, detection_rule]
logsrc_product: "azure"
logsrc_service: "auditlogs"
level: "high"
---

## Changes To PIM Settings

### Description

Detects when changes are made to PIM roles

```yml
title: Changes To PIM Settings
id: db6c06c4-bf3b-421c-aa88-15672b88c743
status: test
description: Detects when changes are made to PIM roles
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-privileged-identity-management#azure-ad-roles-assignment
author: Mark Morowczynski '@markmorow', Yochana Henderson, '@Yochana-H'
date: 2022/08/09
tags:
    - attack.privilege_escalation
    - attack.persistence
    - attack.t1078.004
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        properties.message: Update role setting in PIM
    condition: selection
falsepositives:
    - Legit administrative PIM setting configuration changes
level: high

```
