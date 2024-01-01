---
title: "Successful Authentications From Countries You Do Not Operate Out Of"
status: "test"
created: "2022/07/28"
last_modified: ""
tags: [initial_access, credential_access, t1078_004, t1110, detection_rule]
logsrc_product: "azure"
logsrc_service: "signinlogs"
level: "medium"
---

## Successful Authentications From Countries You Do Not Operate Out Of

### Description

Detect successful authentications from countries you do not operate out of.

```yml
title: Successful Authentications From Countries You Do Not Operate Out Of
id: 8c944ecb-6970-4541-8496-be554b8e2846
status: test
description: Detect successful authentications from countries you do not operate out of.
references:
    - https://docs.microsoft.com/en-gb/azure/active-directory/fundamentals/security-operations-user-accounts
author: MikeDuddington, '@dudders1'
date: 2022/07/28
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
    filter:
        Location|contains: '<Countries you DO operate out of e,g GB, use OR for multiple>'
    condition: selection and not filter
falsepositives:
    - If this was approved by System Administrator.
level: medium

```
