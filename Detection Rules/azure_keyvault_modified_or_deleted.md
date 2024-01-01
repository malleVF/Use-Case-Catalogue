---
title: "Azure Key Vault Modified or Deleted"
status: "test"
created: "2021/08/16"
last_modified: "2022/08/23"
tags: [impact, credential_access, t1552, t1552_001, detection_rule]
logsrc_product: "azure"
logsrc_service: "activitylogs"
level: "medium"
---

## Azure Key Vault Modified or Deleted

### Description

Identifies when a key vault is modified or deleted.

```yml
title: Azure Key Vault Modified or Deleted
id: 459a2970-bb84-4e6a-a32e-ff0fbd99448d
status: test
description: Identifies when a key vault is modified or deleted.
references:
    - https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations
author: Austin Songer @austinsonger
date: 2021/08/16
modified: 2022/08/23
tags:
    - attack.impact
    - attack.credential_access
    - attack.t1552
    - attack.t1552.001
logsource:
    product: azure
    service: activitylogs
detection:
    selection:
        operationName:
            - MICROSOFT.KEYVAULT/VAULTS/WRITE
            - MICROSOFT.KEYVAULT/VAULTS/DELETE
            - MICROSOFT.KEYVAULT/VAULTS/DEPLOY/ACTION
            - MICROSOFT.KEYVAULT/VAULTS/ACCESSPOLICIES/WRITE
    condition: selection
falsepositives:
    - Key Vault being modified or deleted may be performed by a system administrator.
    - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
    - Key Vault modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
level: medium

```
