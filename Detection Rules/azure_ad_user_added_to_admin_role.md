---
title: "User Added to an Administrator's Azure AD Role"
status: "test"
created: "2021/10/04"
last_modified: "2022/10/09"
tags: [persistence, privilege_escalation, t1098_003, t1078, detection_rule]
logsrc_product: "azure"
logsrc_service: "activitylogs"
level: "medium"
---

## User Added to an Administrator's Azure AD Role

### Description

User Added to an Administrator's Azure AD Role

```yml
title: User Added to an Administrator's Azure AD Role
id: ebbeb024-5b1d-4e16-9c0c-917f86c708a7
status: test
description: User Added to an Administrator's Azure AD Role
references:
    - https://m365internals.com/2021/07/13/what-ive-learned-from-doing-a-year-of-cloud-forensics-in-azure-ad/
author: Raphaël CALVET, @MetallicHack
date: 2021/10/04
modified: 2022/10/09
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1098.003
    - attack.t1078
logsource:
    product: azure
    service: activitylogs
detection:
    selection:
        Operation: 'Add member to role.'
        Workload: 'AzureActiveDirectory'
        ModifiedProperties{}.NewValue|endswith:
            - 'Admins'
            - 'Administrator'
    condition: selection
falsepositives:
    - PIM (Privileged Identity Management) generates this event each time 'eligible role' is enabled.
level: medium

```
