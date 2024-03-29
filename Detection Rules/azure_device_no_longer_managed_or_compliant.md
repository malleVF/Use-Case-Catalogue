---
title: "Azure Device No Longer Managed or Compliant"
status: "test"
created: "2021/09/03"
last_modified: "2022/10/09"
tags: [impact, detection_rule]
logsrc_product: "azure"
logsrc_service: "activitylogs"
level: "medium"
---

## Azure Device No Longer Managed or Compliant

### Description

Identifies when a device in azure is no longer managed or compliant

```yml
title: Azure Device No Longer Managed or Compliant
id: 542b9912-c01f-4e3f-89a8-014c48cdca7d
status: test
description: Identifies when a device in azure is no longer managed or compliant
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-audit-activities#core-directory
author: Austin Songer @austinsonger
date: 2021/09/03
modified: 2022/10/09
tags:
    - attack.impact
logsource:
    product: azure
    service: activitylogs
detection:
    selection:
        properties.message:
            - Device no longer compliant
            - Device no longer managed
    condition: selection
falsepositives:
    - Administrator may have forgotten to review the device.
level: medium

```
