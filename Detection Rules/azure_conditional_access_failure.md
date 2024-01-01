---
title: "Sign-in Failure Due to Conditional Access Requirements Not Met"
status: "test"
created: "2022/06/01"
last_modified: ""
tags: [initial_access, credential_access, t1110, t1078_004, detection_rule]
logsrc_product: "azure"
logsrc_service: "signinlogs"
level: "high"
---

## Sign-in Failure Due to Conditional Access Requirements Not Met

### Description

Define a baseline threshold for failed sign-ins due to Conditional Access failures

```yml
title: Sign-in Failure Due to Conditional Access Requirements Not Met
id: b4a6d707-9430-4f5f-af68-0337f52d5c42
status: test
description: Define a baseline threshold for failed sign-ins due to Conditional Access failures
references:
    - https://docs.microsoft.com/en-gb/azure/active-directory/fundamentals/security-operations-privileged-accounts
author: Yochana Henderson, '@Yochana-H'
date: 2022/06/01
tags:
    - attack.initial_access
    - attack.credential_access
    - attack.t1110
    - attack.t1078.004
logsource:
    product: azure
    service: signinlogs
detection:
    selection:
        ResultType: 53003
        Resultdescription: Blocked by Conditional Access
    condition: selection
falsepositives:
    - Service Account misconfigured
    - Misconfigured Systems
    - Vulnerability Scanners
level: high

```
