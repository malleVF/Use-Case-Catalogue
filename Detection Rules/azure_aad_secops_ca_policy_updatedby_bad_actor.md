---
title: "CA Policy Updated by Non Approved Actor"
status: "test"
created: "2022/07/19"
last_modified: ""
tags: [defense_evasion, persistence, t1548, t1556, detection_rule]
logsrc_product: "azure"
logsrc_service: "auditlogs"
level: "medium"
---

## CA Policy Updated by Non Approved Actor

### Description

Monitor and alert on conditional access changes. Is Initiated by (actor) approved to make changes? Review Modified Properties and compare "old" vs "new" value.

```yml
title: CA Policy Updated by Non Approved Actor
id: 50a3c7aa-ec29-44a4-92c1-fce229eef6fc
status: test
description: Monitor and alert on conditional access changes. Is Initiated by (actor) approved to make changes? Review Modified Properties and compare "old" vs "new" value.
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
    keywords:
        - Update conditional access policy
    condition: keywords
falsepositives:
    - Misconfigured role permissions
    - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
level: medium

```
