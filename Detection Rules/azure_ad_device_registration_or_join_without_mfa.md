---
title: "Device Registration or Join Without MFA"
status: "test"
created: "2022/06/28"
last_modified: ""
tags: [defense_evasion, t1078_004, detection_rule]
logsrc_product: "azure"
logsrc_service: "signinlogs"
level: "medium"
---

## Device Registration or Join Without MFA

### Description

Monitor and alert for device registration or join events where MFA was not performed.

```yml
title: Device Registration or Join Without MFA
id: 5afa454e-030c-4ab4-9253-a90aa7fcc581
status: test
description: Monitor and alert for device registration or join events where MFA was not performed.
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-devices#device-registrations-and-joins-outside-policy
author: Michael Epping, '@mepples21'
date: 2022/06/28
tags:
    - attack.defense_evasion
    - attack.t1078.004
logsource:
    product: azure
    service: signinlogs
detection:
    selection:
        ResourceDisplayName: 'Device Registration Service'
        conditionalAccessStatus: 'success'
    filter_mfa:
        AuthenticationRequirement: 'multiFactorAuthentication'
    condition: selection and not filter_mfa
falsepositives:
    - Unknown
level: medium

```
