---
title: "Azure Unusual Authentication Interruption"
status: "test"
created: "2021/11/26"
last_modified: "2022/12/18"
tags: [initial_access, t1078, detection_rule]
logsrc_product: "azure"
logsrc_service: "signinlogs"
level: "medium"
---

## Azure Unusual Authentication Interruption

### Description

Detects when there is a interruption in the authentication process.

```yml
title: Azure Unusual Authentication Interruption
id: 8366030e-7216-476b-9927-271d79f13cf3
status: test
description: Detects when there is a interruption in the authentication process.
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-privileged-accounts
author: Austin Songer @austinsonger
date: 2021/11/26
modified: 2022/12/18
tags:
    - attack.initial_access
    - attack.t1078
logsource:
    product: azure
    service: signinlogs
detection:
    selection_50097:
        ResultType: 50097
        ResultDescription: 'Device authentication is required'
    selection_50155:
        ResultType: 50155
        ResultDescription: 'DeviceAuthenticationFailed'
    selection_50158:
        ResultType: 50158
        ResultDescription: 'ExternalSecurityChallenge - External security challenge was not satisfied'
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: medium

```
