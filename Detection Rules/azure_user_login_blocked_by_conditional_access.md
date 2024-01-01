---
title: "User Access Blocked by Azure Conditional Access"
status: "test"
created: "2021/10/10"
last_modified: "2022/12/25"
tags: [credential_access, initial_access, t1110, t1078_004, detection_rule]
logsrc_product: "azure"
logsrc_service: "signinlogs"
level: "medium"
---

## User Access Blocked by Azure Conditional Access

### Description

Detect access has been blocked by Conditional Access policies.
The access policy does not allow token issuance which might be sights≈ of unauthorizeed login to valid accounts.


```yml
title: User Access Blocked by Azure Conditional Access
id: 9a60e676-26ac-44c3-814b-0c2a8b977adf
status: test
description: |
    Detect access has been blocked by Conditional Access policies.
    The access policy does not allow token issuance which might be sightsâ of unauthorizeed login to valid accounts.
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-privileged-accounts
author: AlertIQ
date: 2021/10/10
modified: 2022/12/25
tags:
    - attack.credential_access
    - attack.initial_access
    - attack.t1110
    - attack.t1078.004
logsource:
    product: azure
    service: signinlogs
detection:
    selection:
        ResultType: 53003
    condition: selection
falsepositives:
    - Unknown
level: medium

```
