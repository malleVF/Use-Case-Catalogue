---
title: "Suspicious SignIns From A Non Registered Device"
status: "test"
created: "2023/01/10"
last_modified: ""
tags: [defense_evasion, t1078, detection_rule]
logsrc_product: "azure"
logsrc_service: "signinlogs"
level: "high"
---

## Suspicious SignIns From A Non Registered Device

### Description

Detects risky authencaition from a non AD registered device without MFA being required.

```yml
title: Suspicious SignIns From A Non Registered Device
id: 572b12d4-9062-11ed-a1eb-0242ac120002
status: test
description: Detects risky authencaition from a non AD registered device without MFA being required.
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-devices#non-compliant-device-sign-in
author: Harjot Singh, '@cyb3rjy0t'
date: 2023/01/10
tags:
    - attack.defense_evasion
    - attack.t1078
logsource:
    product: azure
    service: signinlogs
detection:
    selection:
        Status: 'Success'
        AuthenticationRequirement: 'singleFactorAuthentication'
        DeviceDetail.trusttype: ''
        RiskState: 'atRisk'
    condition: selection
falsepositives:
    - Unknown
level: high

```
