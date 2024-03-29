---
title: "Password Spray Activity"
status: "experimental"
created: "2023/09/03"
last_modified: ""
tags: [t1110, credential_access, detection_rule]
logsrc_product: "azure"
logsrc_service: "riskdetection"
level: "high"
---

## Password Spray Activity

### Description

Indicates that a password spray attack has been successfully performed.

```yml
title: Password Spray Activity
id: 28ecba0a-c743-4690-ad29-9a8f6f25a6f9
status: experimental
description: Indicates that a password spray attack has been successfully performed.
references:
    - https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/concept-identity-protection-risks#password-spray
    - https://learn.microsoft.com/en-us/azure/active-directory/architecture/security-operations-user-accounts#unusual-sign-ins
author: Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
date: 2023/09/03
tags:
    - attack.t1110
    - attack.credential_access
logsource:
    product: azure
    service: riskdetection
detection:
    selection:
        riskEventType: 'passwordSpray'
    condition: selection
falsepositives:
    - We recommend investigating the sessions flagged by this detection in the context of other sign-ins from the user.
level: high

```
