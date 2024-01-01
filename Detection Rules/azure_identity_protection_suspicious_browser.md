---
title: "Suspicious Browser Activity"
status: "experimental"
created: "2023/09/03"
last_modified: ""
tags: [t1078, persistence, defense_evasion, privilege_escalation, initial_access, detection_rule]
logsrc_product: "azure"
logsrc_service: "riskdetection"
level: "high"
---

## Suspicious Browser Activity

### Description

Indicates anomalous behavior based on suspicious sign-in activity across multiple tenants from different countries in the same browser

```yml
title: Suspicious Browser Activity
id: 944f6adb-7a99-4c69-80c1-b712579e93e6
status: experimental
description: Indicates anomalous behavior based on suspicious sign-in activity across multiple tenants from different countries in the same browser
references:
    - https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/concept-identity-protection-risks#suspicious-browser
    - https://learn.microsoft.com/en-us/azure/active-directory/architecture/security-operations-user-accounts#unusual-sign-ins
author: Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
date: 2023/09/03
tags:
    - attack.t1078
    - attack.persistence
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.initial_access
logsource:
    product: azure
    service: riskdetection
detection:
    selection:
        riskEventType: 'suspiciousBrowser'
    condition: selection
falsepositives:
    - We recommend investigating the sessions flagged by this detection in the context of other sign-ins from the user.
level: high

```
