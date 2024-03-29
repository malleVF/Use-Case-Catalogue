---
title: "User Added to Local Administrators"
status: "stable"
created: "2017/03/14"
last_modified: "2021/01/17"
tags: [privilege_escalation, t1078, persistence, t1098, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "medium"
---

## User Added to Local Administrators

### Description

This rule triggers on user accounts that are added to the local Administrators group, which could be legitimate activity or a sign of privilege escalation activity

```yml
title: User Added to Local Administrators
id: c265cf08-3f99-46c1-8d59-328247057d57
status: stable
description: This rule triggers on user accounts that are added to the local Administrators group, which could be legitimate activity or a sign of privilege escalation activity
author: Florian Roth (Nextron Systems)
date: 2017/03/14
modified: 2021/01/17
tags:
    - attack.privilege_escalation
    - attack.t1078
    - attack.persistence
    - attack.t1098
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4732
    selection_group1:
        TargetUserName|startswith: 'Administr'
    selection_group2:
        TargetSid: 'S-1-5-32-544'
    filter:
        SubjectUserName|endswith: '$'
    condition: selection and (1 of selection_group*) and not filter
falsepositives:
    - Legitimate administrative activity
level: medium

```
