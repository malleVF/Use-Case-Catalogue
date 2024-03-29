---
title: "New CA Policy by Non-approved Actor"
status: "test"
created: "2022/07/18"
last_modified: ""
tags: [defense_evasion, t1548, detection_rule]
logsrc_product: "azure"
logsrc_service: "auditlogs"
level: "medium"
---

## New CA Policy by Non-approved Actor

### Description

Monitor and alert on conditional access changes.

```yml
title: New CA Policy by Non-approved Actor
id: 0922467f-db53-4348-b7bf-dee8d0d348c6
status: test
description: Monitor and alert on conditional access changes.
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-infrastructure
author: Corissa Koopmans, '@corissalea'
date: 2022/07/18
tags:
    - attack.defense_evasion
    - attack.t1548
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        properties.message: Add conditional access policy
    condition: selection
falsepositives:
    - Misconfigured role permissions
    - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
level: medium

```
