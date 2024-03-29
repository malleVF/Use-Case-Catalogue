---
title: "Guest User Invited By Non Approved Inviters"
status: "test"
created: "2022/08/10"
last_modified: ""
tags: [persistence, defense_evasion, t1078_004, detection_rule]
logsrc_product: "azure"
logsrc_service: "auditlogs"
level: "medium"
---

## Guest User Invited By Non Approved Inviters

### Description

Detects when a user that doesn't have permissions to invite a guest user attempts to invite one.

```yml
title: Guest User Invited By Non Approved Inviters
id: 0b4b72e3-4c53-4d5b-b198-2c58cfef39a9
status: test
description: Detects when a user that doesn't have permissions to invite a guest user attempts to invite one.
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-privileged-accounts#things-to-monitor
author: Mark Morowczynski '@markmorow', Yochana Henderson, '@Yochana-H'
date: 2022/08/10
tags:
    - attack.persistence
    - attack.defense_evasion
    - attack.t1078.004
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        properties.message: Invite external user
        Status: failure
    condition: selection
falsepositives:
    - A non malicious user is unaware of the proper process
level: medium

```
