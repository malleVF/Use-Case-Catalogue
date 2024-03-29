---
title: "Login to Disabled Account"
status: "test"
created: "2021/10/10"
last_modified: "2022/12/25"
tags: [initial_access, t1078_004, detection_rule]
logsrc_product: "azure"
logsrc_service: "signinlogs"
level: "medium"
---

## Login to Disabled Account

### Description

Detect failed attempts to sign in to disabled accounts.

```yml
title: Login to Disabled Account
id: 908655e0-25cf-4ae1-b775-1c8ce9cf43d8
status: test
description: Detect failed attempts to sign in to disabled accounts.
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-privileged-accounts
author: AlertIQ
date: 2021/10/10
modified: 2022/12/25
tags:
    - attack.initial_access
    - attack.t1078.004
logsource:
    product: azure
    service: signinlogs
detection:
    selection:
        ResultType: 50057
        ResultDescription: 'User account is disabled. The account has been disabled by an administrator.'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
