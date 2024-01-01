---
title: "Azure VPN Connection Modified or Deleted"
status: "test"
created: "2021/08/08"
last_modified: "2022/08/23"
tags: [impact, detection_rule]
logsrc_product: "azure"
logsrc_service: "activitylogs"
level: "medium"
---

## Azure VPN Connection Modified or Deleted

### Description

Identifies when a VPN connection is modified or deleted.

```yml
title: Azure VPN Connection Modified or Deleted
id: 61171ffc-d79c-4ae5-8e10-9323dba19cd3
status: test
description: Identifies when a VPN connection is modified or deleted.
references:
    - https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations
author: Austin Songer @austinsonger
date: 2021/08/08
modified: 2022/08/23
tags:
    - attack.impact
logsource:
    product: azure
    service: activitylogs
detection:
    selection:
        operationName:
            - MICROSOFT.NETWORK/VPNGATEWAYS/VPNCONNECTIONS/WRITE
            - MICROSOFT.NETWORK/VPNGATEWAYS/VPNCONNECTIONS/DELETE
    condition: selection
falsepositives:
    - VPN Connection being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
    - VPN Connection modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
level: medium

```
