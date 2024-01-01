---
title: "Azure Network Firewall Policy Modified or Deleted"
status: "test"
created: "2021/09/02"
last_modified: "2022/08/23"
tags: [impact, defense_evasion, t1562_007, detection_rule]
logsrc_product: "azure"
logsrc_service: "activitylogs"
level: "medium"
---

## Azure Network Firewall Policy Modified or Deleted

### Description

Identifies when a Firewall Policy is Modified or Deleted.

```yml
title: Azure Network Firewall Policy Modified or Deleted
id: 83c17918-746e-4bd9-920b-8e098bf88c23
status: test
description: Identifies when a Firewall Policy is Modified or Deleted.
references:
    - https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations
author: Austin Songer @austinsonger
date: 2021/09/02
modified: 2022/08/23
tags:
    - attack.impact
    - attack.defense_evasion
    - attack.t1562.007
logsource:
    product: azure
    service: activitylogs
detection:
    selection:
        operationName:
            - MICROSOFT.NETWORK/FIREWALLPOLICIES/WRITE
            - MICROSOFT.NETWORK/FIREWALLPOLICIES/JOIN/ACTION
            - MICROSOFT.NETWORK/FIREWALLPOLICIES/CERTIFICATES/ACTION
            - MICROSOFT.NETWORK/FIREWALLPOLICIES/DELETE
    condition: selection
falsepositives:
    - Firewall Policy being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
    - Firewall Policy modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
level: medium

```
