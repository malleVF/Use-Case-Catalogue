---
title: "Activity from Infrequent Country"
status: "test"
created: "2021/08/23"
last_modified: "2022/10/09"
tags: [command_and_control, t1573, detection_rule]
logsrc_product: "m365"
logsrc_service: "threat_management"
level: "medium"
---

## Activity from Infrequent Country

### Description

Detects when a Microsoft Cloud App Security reported when an activity occurs from a location that wasn't recently or never visited by any user in the organization.

```yml
title: Activity from Infrequent Country
id: 0f2468a2-5055-4212-a368-7321198ee706
status: test
description: Detects when a Microsoft Cloud App Security reported when an activity occurs from a location that wasn't recently or never visited by any user in the organization.
references:
    - https://docs.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy
    - https://docs.microsoft.com/en-us/cloud-app-security/policy-template-reference
author: Austin Songer @austinsonger
date: 2021/08/23
modified: 2022/10/09
tags:
    - attack.command_and_control
    - attack.t1573
logsource:
    service: threat_management
    product: m365
detection:
    selection:
        eventSource: SecurityComplianceCenter
        eventName: 'Activity from infrequent country'
        status: success
    condition: selection
falsepositives:
    - Unknown
level: medium

```
