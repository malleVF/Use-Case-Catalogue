---
title: "Bitlocker Key Retrieval"
status: "test"
created: "2022/06/28"
last_modified: ""
tags: [defense_evasion, t1078_004, detection_rule]
logsrc_product: "azure"
logsrc_service: "auditlogs"
level: "medium"
---

## Bitlocker Key Retrieval

### Description

Monitor and alert for Bitlocker key retrieval.

```yml
title: Bitlocker Key Retrieval
id: a0413867-daf3-43dd-9245-734b3a787942
status: test
description: Monitor and alert for Bitlocker key retrieval.
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-devices#bitlocker-key-retrieval
author: Michael Epping, '@mepples21'
date: 2022/06/28
tags:
    - attack.defense_evasion
    - attack.t1078.004
logsource:
    product: azure
    service: auditlogs
detection:
    selection:
        Category: KeyManagement
        OperationName: Read BitLocker key
    condition: selection
falsepositives:
    - Unknown
level: medium

```
