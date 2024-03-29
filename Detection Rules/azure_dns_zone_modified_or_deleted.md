---
title: "Azure DNS Zone Modified or Deleted"
status: "test"
created: "2021/08/08"
last_modified: "2022/08/23"
tags: [impact, t1565_001, detection_rule]
logsrc_product: "azure"
logsrc_service: "activitylogs"
level: "medium"
---

## Azure DNS Zone Modified or Deleted

### Description

Identifies when DNS zone is modified or deleted.

```yml
title: Azure DNS Zone Modified or Deleted
id: af6925b0-8826-47f1-9324-337507a0babd
status: test
description: Identifies when DNS zone is modified or deleted.
references:
    - https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes
author: Austin Songer @austinsonger
date: 2021/08/08
modified: 2022/08/23
tags:
    - attack.impact
    - attack.t1565.001
logsource:
    product: azure
    service: activitylogs
detection:
    selection:
        operationName|startswith: 'MICROSOFT.NETWORK/DNSZONES'
        operationName|endswith:
            - '/WRITE'
            - '/DELETE'
    condition: selection
falsepositives:
    - DNS zone modified and deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
    - DNS zone modification from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
level: medium

```
