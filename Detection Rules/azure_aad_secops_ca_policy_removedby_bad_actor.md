---
title: "CA Policy Removed by Non Approved Actor"
status: "test"
created: "2022/07/19"
last_modified: ""
tags: [defense_evasion, persistence, t1548, t1556, detection_rule]
logsrc_product: "azure"
logsrc_service: "auditlogs"
level: "medium"
---

## CA Policy Removed by Non Approved Actor

### Description

Monitor and alert on conditional access changes where non approved actor removed CA Policy.

```yml
title: CA Policy Removed by Non Approved Actor
id: 26e7c5e2-6545-481e-b7e6-050143459635
status: test
description: Monitor and alert on conditional access changes where non approved actor removed CA Policy.
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-infrastructure#conditional-access
author: Corissa Koopmans, '@corissalea'
date: 2022/07/19
tags:
    - attack.defense_evasion
    - attack.persistence
    - attack.t1548
    - attack.t1556
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        properties.message: Delete conditional access policy
    condition: selection
falsepositives:
    - Misconfigured role permissions
    - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
level: medium

```
