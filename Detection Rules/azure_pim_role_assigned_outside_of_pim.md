---
title: "Roles Assigned Outside PIM"
status: "experimental"
created: "2023/09/14"
last_modified: ""
tags: [t1078, persistence, privilege_escalation, detection_rule]
logsrc_product: "azure"
logsrc_service: "pim"
level: "high"
---

## Roles Assigned Outside PIM

### Description

Identifies when a privilege role assignment has taken place outside of PIM and may indicate an attack.

```yml
title: Roles Assigned Outside PIM
id: b1bc08d1-8224-4758-a0e6-fbcfc98c73bb
status: experimental
description: Identifies when a privilege role assignment has taken place outside of PIM and may indicate an attack.
references:
    - https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-how-to-configure-security-alerts#roles-are-being-assigned-outside-of-privileged-identity-management
author: Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
date: 2023/09/14
tags:
    - attack.t1078
    - attack.persistence
    - attack.privilege_escalation
logsource:
    product: azure
    service: pim
detection:
    selection:
        riskEventType: 'rolesAssignedOutsidePrivilegedIdentityManagementAlertConfiguration'
    condition: selection
falsepositives:
    - Investigate where users are being assigned privileged roles outside of Privileged Identity Management and prohibit future assignments from there.
level: high

```
