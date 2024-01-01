---
title: "Authentications To Important Apps Using Single Factor Authentication"
status: "test"
created: "2022/07/28"
last_modified: ""
tags: [initial_access, t1078, detection_rule]
logsrc_product: "azure"
logsrc_service: "signinlogs"
level: "medium"
---

## Authentications To Important Apps Using Single Factor Authentication

### Description

Detect when authentications to important application(s) only required single-factor authentication

```yml
title: Authentications To Important Apps Using Single Factor Authentication
id: f272fb46-25f2-422c-b667-45837994980f
status: test
description: Detect when authentications to important application(s) only required single-factor authentication
references:
    - https://docs.microsoft.com/en-gb/azure/active-directory/fundamentals/security-operations-user-accounts
author: MikeDuddington, '@dudders1'
date: 2022/07/28
tags:
    - attack.initial_access
    - attack.t1078
logsource:
    product: azure
    service: signinlogs
detection:
    selection:
        Status: 'Success'
        AppId: 'Insert Application ID use OR for multiple'
        AuthenticationRequirement: 'singleFactorAuthentication'
    condition: selection
falsepositives:
    - If this was approved by System Administrator.
level: medium

```
