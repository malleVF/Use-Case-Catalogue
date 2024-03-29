---
title: "Application Using Device Code Authentication Flow"
status: "test"
created: "2022/06/01"
last_modified: ""
tags: [t1078, defense_evasion, persistence, privilege_escalation, initial_access, detection_rule]
logsrc_product: "azure"
logsrc_service: "signinlogs"
level: "medium"
---

## Application Using Device Code Authentication Flow

### Description

Device code flow is an OAuth 2.0 protocol flow specifically for input constrained devices and is not used in all environments.
If this type of flow is seen in the environment and not being used in an input constrained device scenario, further investigation is warranted.
This can be a misconfigured application or potentially something malicious.


```yml
title: Application Using Device Code Authentication Flow
id: 248649b7-d64f-46f0-9fb2-a52774166fb5
status: test
description: |
    Device code flow is an OAuth 2.0 protocol flow specifically for input constrained devices and is not used in all environments.
    If this type of flow is seen in the environment and not being used in an input constrained device scenario, further investigation is warranted.
    This can be a misconfigured application or potentially something malicious.
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-applications#application-authentication-flows
author: Mark Morowczynski '@markmorow', Bailey Bercik '@baileybercik'
date: 2022/06/01
tags:
    - attack.t1078
    - attack.defense_evasion
    - attack.persistence
    - attack.privilege_escalation
    - attack.initial_access
logsource:
    product: azure
    service: signinlogs
detection:
    selection:
        properties.message: Device Code
    condition: selection
falsepositives:
    - Applications that are input constrained will need to use device code flow and are valid authentications.
level: medium

```
