---
title: "Increased Failed Authentications Of Any Type"
status: "test"
created: "2022/08/11"
last_modified: ""
tags: [defense_evasion, t1078, detection_rule]
logsrc_product: "azure"
logsrc_service: "signinlogs"
level: "medium"
---

## Increased Failed Authentications Of Any Type

### Description

Detects when sign-ins increased by 10% or greater.

```yml
title: Increased Failed Authentications Of Any Type
id: e1d02b53-c03c-4948-b11d-4d00cca49d03
status: test
description: Detects when sign-ins increased by 10% or greater.
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-user-accounts#monitoring-for-failed-unusual-sign-ins
author: Mark Morowczynski '@markmorow', MikeDuddington, '@dudders1'
date: 2022/08/11
tags:
    - attack.defense_evasion
    - attack.t1078
logsource:
    product: azure
    service: signinlogs
detection:
    selection:
        Status: failure
        Count: "<10%"
    condition: selection
falsepositives:
    - Unlikely
level: medium

```
