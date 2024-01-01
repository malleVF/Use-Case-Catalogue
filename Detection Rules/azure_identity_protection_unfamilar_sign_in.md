---
title: "Unfamiliar Sign-In Properties"
status: "experimental"
created: "2023/09/03"
last_modified: ""
tags: [t1078, persistence, defense_evasion, privilege_escalation, initial_access, detection_rule]
logsrc_product: "azure"
logsrc_service: "riskdetection"
level: "high"
---

## Unfamiliar Sign-In Properties

### Description

Detects sign-in with properties that are unfamiliar to the user. The detection considers past sign-in history to look for anomalous sign-ins.

```yml
title: Unfamiliar Sign-In Properties
id: 128faeef-79dd-44ca-b43c-a9e236a60f49
status: experimental
description: Detects sign-in with properties that are unfamiliar to the user. The detection considers past sign-in history to look for anomalous sign-ins.
references:
    - https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/concept-identity-protection-risks#unfamiliar-sign-in-properties
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
        riskEventType: 'unfamiliarFeatures'
    condition: selection
falsepositives:
    - User changing to a new device, location, browser, etc.
level: high

```
