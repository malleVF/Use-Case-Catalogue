---
title: "User Added To Group With CA Policy Modification Access"
status: "test"
created: "2022/08/04"
last_modified: ""
tags: [defense_evasion, persistence, t1548, t1556, detection_rule]
logsrc_product: "azure"
logsrc_service: "auditlogs"
level: "medium"
---

## User Added To Group With CA Policy Modification Access

### Description

Monitor and alert on group membership additions of groups that have CA policy modification access

```yml
title: User Added To Group With CA Policy Modification Access
id: 91c95675-1f27-46d0-bead-d1ae96b97cd3
status: test
description: Monitor and alert on group membership additions of groups that have CA policy modification access
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
        properties.message: Add member from group
    condition: selection
falsepositives:
    - User removed from the group is approved
level: medium

```
