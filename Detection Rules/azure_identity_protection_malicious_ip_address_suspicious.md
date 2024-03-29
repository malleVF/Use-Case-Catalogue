---
title: "Malicious IP Address Sign-In Suspicious"
status: "experimental"
created: "2023/09/07"
last_modified: ""
tags: [t1090, command_and_control, detection_rule]
logsrc_product: "azure"
logsrc_service: "riskdetection"
level: "high"
---

## Malicious IP Address Sign-In Suspicious

### Description

Indicates sign-in from a malicious IP address known to be malicious at time of sign-in.

```yml
title: Malicious IP Address Sign-In Suspicious
id: 36440e1c-5c22-467a-889b-593e66498472
status: experimental
description: Indicates sign-in from a malicious IP address known to be malicious at time of sign-in.
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
        riskEventType: 'suspiciousIPAddress'
    condition: selection
falsepositives:
    - We recommend investigating the sessions flagged by this detection in the context of other sign-ins from the user.
level: high

```
