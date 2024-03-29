---
title: "Temporary Access Pass Added To An Account"
status: "test"
created: "2022/08/10"
last_modified: ""
tags: [persistence, t1078_004, detection_rule]
logsrc_product: "azure"
logsrc_service: "auditlogs"
level: "high"
---

## Temporary Access Pass Added To An Account

### Description

Detects when a temporary access pass (TAP) is added to an account. TAPs added to priv accounts should be investigated

```yml
title: Temporary Access Pass Added To An Account
id: fa84aaf5-8142-43cd-9ec2-78cfebf878ce
status: test
description: Detects when a temporary access pass (TAP) is added to an account. TAPs added to priv accounts should be investigated
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-privileged-accounts#changes-to-privileged-accounts
author: Mark Morowczynski '@markmorow', Yochana Henderson, '@Yochana-H'
date: 2022/08/10
tags:
    - attack.persistence
    - attack.t1078.004
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        properties.message: Admin registered security info
        Status: Admin registered temporary access pass method for user
    condition: selection
falsepositives:
    - Administrator adding a legitimate temporary access pass
level: high

```
