---
title: "Account Disabled or Blocked for Sign in Attempts"
status: "test"
created: "2022/06/17"
last_modified: ""
tags: [initial_access, t1078_004, detection_rule]
logsrc_product: "azure"
logsrc_service: "signinlogs"
level: "medium"
---

## Account Disabled or Blocked for Sign in Attempts

### Description

Detects when an account is disabled or blocked for sign in but tried to log in

```yml
title: Account Disabled or Blocked for Sign in Attempts
id: 4afac85c-224a-4dd7-b1af-8da40e1c60bd
status: test
description: Detects when an account is disabled or blocked for sign in but tried to log in
references:
    - https://docs.microsoft.com/en-gb/azure/active-directory/fundamentals/security-operations-privileged-accounts
author: Yochana Henderson, '@Yochana-H'
date: 2022/06/17
tags:
    - attack.initial_access
    - attack.t1078.004
logsource:
    product: azure
    service: signinlogs
detection:
    selection:
        ResultType: 50057
        ResultDescription: Failure
    condition: selection
falsepositives:
    - Account disabled or blocked in error
    - Automation account has been blocked or disabled
level: medium

```
