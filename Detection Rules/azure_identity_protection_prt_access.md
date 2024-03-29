---
title: "Primary Refresh Token Access Attempt"
status: "experimental"
created: "2023/09/07"
last_modified: ""
tags: [t1528, credential_access, detection_rule]
logsrc_product: "azure"
logsrc_service: "riskdetection"
level: "high"
---

## Primary Refresh Token Access Attempt

### Description

Indicates access attempt to the PRT resource which can be used to move laterally into an organization or perform credential theft

```yml
title: Primary Refresh Token Access Attempt
id: a84fc3b1-c9ce-4125-8e74-bdcdb24021f1
status: experimental
description: Indicates access attempt to the PRT resource which can be used to move laterally into an organization or perform credential theft
references:
    - https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/concept-identity-protection-risks#possible-attempt-to-access-primary-refresh-token-prt
    - https://learn.microsoft.com/en-us/azure/active-directory/architecture/security-operations-user-accounts#unusual-sign-ins
author: Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
date: 2023/09/07
tags:
    - attack.t1528
    - attack.credential_access
logsource:
    product: azure
    service: riskdetection
detection:
    selection:
        riskEventType: 'attemptedPrtAccess'
    condition: selection
falsepositives:
    - This detection is low-volume and is seen infrequently in most organizations. When this detection appears it's high risk, and users should be remediated.
level: high

```
