---
title: "New Country"
status: "experimental"
created: "2023/09/03"
last_modified: ""
tags: [t1078, persistence, defense_evasion, privilege_escalation, initial_access, detection_rule]
logsrc_product: "azure"
logsrc_service: "riskdetection"
level: "high"
---

## New Country

### Description

Detects sign-ins from new countries. The detection considers past activity locations to determine new and infrequent locations.

```yml
title: New Country
id: adf9f4d2-559e-4f5c-95be-c28dff0b1476
status: experimental
description: Detects sign-ins from new countries. The detection considers past activity locations to determine new and infrequent locations.
references:
    - https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/concept-identity-protection-risks#new-country
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
        riskEventType: 'newCountry'
    condition: selection
falsepositives:
    - We recommend investigating the sessions flagged by this detection in the context of other sign-ins from the user.
level: high

```
