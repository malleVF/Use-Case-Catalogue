---
title: "Azure AD Account Credential Leaked"
status: "experimental"
created: "2023/09/03"
last_modified: ""
tags: [t1589, reconnaissance, detection_rule]
logsrc_product: "azure"
logsrc_service: "riskdetection"
level: "high"
---

## Azure AD Account Credential Leaked

### Description

Indicates that the user's valid credentials have been leaked.

```yml
title: Azure AD Account Credential Leaked
id: 19128e5e-4743-48dc-bd97-52e5775af817
status: experimental
description: Indicates that the user's valid credentials have been leaked.
references:
    - https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/concept-identity-protection-risks#leaked-credentials
    - https://learn.microsoft.com/en-us/azure/active-directory/architecture/security-operations-user-accounts#unusual-sign-ins
author: Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
date: 2023/09/03
tags:
    - attack.t1589
    - attack.reconnaissance
logsource:
    product: azure
    service: riskdetection
detection:
    selection:
        riskEventType: 'leakedCredentials'
    condition: selection
falsepositives:
    - A rare hash collision.
level: high

```
