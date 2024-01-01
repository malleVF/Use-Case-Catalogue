---
title: "Activity From Anonymous IP Address"
status: "experimental"
created: "2023/09/03"
last_modified: ""
tags: [t1078, persistence, defense_evasion, privilege_escalation, initial_access, detection_rule]
logsrc_product: "azure"
logsrc_service: "riskdetection"
level: "high"
---

## Activity From Anonymous IP Address

### Description

Identifies that users were active from an IP address that has been identified as an anonymous proxy IP address.

```yml
title: Activity From Anonymous IP Address
id: be4d9c86-d702-4030-b52e-c7859110e5e8
status: experimental
description: Identifies that users were active from an IP address that has been identified as an anonymous proxy IP address.
references:
    - https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/concept-identity-protection-risks#activity-from-anonymous-ip-address
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
        riskEventType: 'riskyIPAddress'
    condition: selection
falsepositives:
    - We recommend investigating the sessions flagged by this detection in the context of other sign-ins from the user.
level: high

```
