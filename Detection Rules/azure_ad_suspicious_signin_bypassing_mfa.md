---
title: "Potential MFA Bypass Using Legacy Client Authentication"
status: "experimental"
created: "2023/03/20"
last_modified: ""
tags: [initial_access, credential_access, t1078_004, t1110, detection_rule]
logsrc_product: "azure"
logsrc_service: "signinlogs"
level: "high"
---

## Potential MFA Bypass Using Legacy Client Authentication

### Description

Detects successful authentication from potential clients using legacy authentication via user agent strings. This could be a sign of MFA bypass using a password spray attack.

```yml
title: Potential MFA Bypass Using Legacy Client Authentication
id: 53bb4f7f-48a8-4475-ac30-5a82ddfdf6fc
status: experimental
description: Detects successful authentication from potential clients using legacy authentication via user agent strings. This could be a sign of MFA bypass using a password spray attack.
references:
    - https://blooteem.com/march-2022
    - https://www.microsoft.com/en-us/security/blog/2021/10/26/protect-your-business-from-password-sprays-with-microsoft-dart-recommendations/
author: Harjot Singh, '@cyb3rjy0t'
date: 2023/03/20
tags:
    - attack.initial_access
    - attack.credential_access
    - attack.t1078.004
    - attack.t1110
logsource:
    product: azure
    service: signinlogs
detection:
    selection:
        Status: 'Success'
        userAgent|contains:
            - 'BAV2ROPC'
            - 'CBAinPROD'
            - 'CBAinTAR'
    condition: selection
falsepositives:
    - Known Legacy Accounts
level: high

```
