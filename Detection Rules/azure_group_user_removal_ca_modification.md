---
title: "User Removed From Group With CA Policy Modification Access"
status: "test"
created: "2022/08/04"
last_modified: ""
tags: [defense_evasion, persistence, t1548, t1556, detection_rule]
logsrc_product: "azure"
logsrc_service: "auditlogs"
level: "medium"
---

## User Removed From Group With CA Policy Modification Access

### Description

Monitor and alert on group membership removal of groups that have CA policy modification access

```yml
title: User Removed From Group With CA Policy Modification Access
id: 665e2d43-70dc-4ccc-9d27-026c9dd7ed9c
status: test
description: Monitor and alert on group membership removal of groups that have CA policy modification access
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-infrastructure#conditional-access
author: Mark Morowczynski '@markmorow', Thomas Detzner '@tdetzner'
date: 2022/08/04
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
        properties.message: Remove member from group
    condition: selection
falsepositives:
    - User removed from the group is approved
level: medium

```
