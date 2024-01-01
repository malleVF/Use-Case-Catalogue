---
title: "Azure Service Principal Removed"
status: "test"
created: "2021/09/03"
last_modified: "2022/10/09"
tags: [defense_evasion, detection_rule]
logsrc_product: "azure"
logsrc_service: "activitylogs"
level: "medium"
---

## Azure Service Principal Removed

### Description

Identifies when a service principal was removed in Azure.

```yml
title: Azure Service Principal Removed
id: 448fd1ea-2116-4c62-9cde-a92d120e0f08
status: test
description: Identifies when a service principal was removed in Azure.
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-audit-activities#application-proxy
author: Austin Songer @austinsonger
date: 2021/09/03
modified: 2022/10/09
tags:
    - attack.defense_evasion
logsource:
    product: azure
    service: activitylogs
detection:
    selection:
        properties.message: Remove service principal
    condition: selection
falsepositives:
    - Service principal being removed may be performed by a system administrator.
    - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
    - Service principal removed from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
level: medium

```
