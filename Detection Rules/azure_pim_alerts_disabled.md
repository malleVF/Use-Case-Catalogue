---
title: "PIM Alert Setting Changes To Disabled"
status: "test"
created: "2022/08/09"
last_modified: ""
tags: [persistence, privilege_escalation, t1078, detection_rule]
logsrc_product: "azure"
logsrc_service: "auditlogs"
level: "high"
---

## PIM Alert Setting Changes To Disabled

### Description

Detects when PIM alerts are set to disabled.

```yml
title: PIM Alert Setting Changes To Disabled
id: aeaef14c-e5bf-4690-a9c8-835caad458bd
status: test
description: Detects when PIM alerts are set to disabled.
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-privileged-identity-management#azure-ad-roles-assignment
author: Mark Morowczynski '@markmorow', Yochana Henderson, '@Yochana-H'
date: 2022/08/09
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1078
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        properties.message: Disable PIM Alert
    condition: selection
falsepositives:
    - Administrator disabling PIM alerts as an active choice.
level: high

```
