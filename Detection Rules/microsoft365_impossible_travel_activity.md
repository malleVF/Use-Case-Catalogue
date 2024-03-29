---
title: "Microsoft 365 - Impossible Travel Activity"
status: "test"
created: "2020/07/06"
last_modified: "2021/11/27"
tags: [initial_access, t1078, detection_rule]
logsrc_product: "m365"
logsrc_service: "threat_management"
level: "medium"
---

## Microsoft 365 - Impossible Travel Activity

### Description

Detects when a Microsoft Cloud App Security reported a risky sign-in attempt due to a login associated with an impossible travel.

```yml
title: Microsoft 365 - Impossible Travel Activity
id: d7eab125-5f94-43df-8710-795b80fa1189
status: test
description: Detects when a Microsoft Cloud App Security reported a risky sign-in attempt due to a login associated with an impossible travel.
references:
    - https://docs.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy
    - https://docs.microsoft.com/en-us/cloud-app-security/policy-template-reference
author: Austin Songer @austinsonger
date: 2020/07/06
modified: 2021/11/27
tags:
    - attack.initial_access
    - attack.t1078
logsource:
    service: threat_management
    product: m365
detection:
    selection:
        eventSource: SecurityComplianceCenter
        eventName: 'Impossible travel activity'
        status: success
    condition: selection
falsepositives:
    - Unknown
level: medium

```
