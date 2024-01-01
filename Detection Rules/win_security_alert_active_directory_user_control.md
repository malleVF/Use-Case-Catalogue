---
title: "Enabled User Right in AD to Control User Objects"
status: "test"
created: "2017/07/30"
last_modified: "2021/12/02"
tags: [persistence, t1098, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## Enabled User Right in AD to Control User Objects

### Description

Detects scenario where if a user is assigned the SeEnableDelegationPrivilege right in Active Directory it would allow control of other AD user objects.

```yml
title: Enabled User Right in AD to Control User Objects
id: 311b6ce2-7890-4383-a8c2-663a9f6b43cd
status: test
description: Detects scenario where if a user is assigned the SeEnableDelegationPrivilege right in Active Directory it would allow control of other AD user objects.
references:
    - https://blog.harmj0y.net/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/
author: '@neu5ron'
date: 2017/07/30
modified: 2021/12/02
tags:
    - attack.persistence
    - attack.t1098
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : Policy Change > Audit Authorization Policy Change, Group Policy : Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Policy Change\Audit Authorization Policy Change'
detection:
    selection_base:
        EventID: 4704
    selection_keywords:
        PrivilegeList|contains: 'SeEnableDelegationPrivilege'
    condition: all of selection*
falsepositives:
    - Unknown
level: high

```