---
title: "Malicious IP Address Sign-In Failure Rate"
status: "experimental"
created: "2023/09/07"
last_modified: ""
tags: [t1090, command_and_control, detection_rule]
logsrc_product: "azure"
logsrc_service: "riskdetection"
level: "high"
---

## Malicious IP Address Sign-In Failure Rate

### Description

Indicates sign-in from a malicious IP address based on high failure rates.

```yml
title: Malicious IP Address Sign-In Failure Rate
id: a3f55ebd-0c01-4ed6-adc0-8fb76d8cd3cd
status: experimental
description: Indicates sign-in from a malicious IP address based on high failure rates.
references:
    - https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/concept-identity-protection-risks#malicious-ip-address
    - https://learn.microsoft.com/en-us/azure/active-directory/architecture/security-operations-user-accounts#unusual-sign-ins
author: Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
date: 2023/09/07
tags:
    - attack.t1090
    - attack.command_and_control
logsource:
    product: azure
    service: riskdetection
detection:
    selection:
        riskEventType: 'maliciousIPAddress'
    condition: selection
falsepositives:
    - We recommend investigating the sessions flagged by this detection in the context of other sign-ins from the user.
level: high

```
