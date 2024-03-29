---
title: "Microsoft 365 - Potential Ransomware Activity"
status: "test"
created: "2021/08/19"
last_modified: "2022/10/09"
tags: [impact, t1486, detection_rule]
logsrc_product: "m365"
logsrc_service: "threat_management"
level: "medium"
---

## Microsoft 365 - Potential Ransomware Activity

### Description

Detects when a Microsoft Cloud App Security reported when a user uploads files to the cloud that might be infected with ransomware.

```yml
title: Microsoft 365 - Potential Ransomware Activity
id: bd132164-884a-48f1-aa2d-c6d646b04c69
status: test
description: Detects when a Microsoft Cloud App Security reported when a user uploads files to the cloud that might be infected with ransomware.
references:
    - https://docs.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy
    - https://docs.microsoft.com/en-us/cloud-app-security/policy-template-reference
author: austinsonger
date: 2021/08/19
modified: 2022/10/09
tags:
    - attack.impact
    - attack.t1486
logsource:
    service: threat_management
    product: m365
detection:
    selection:
        eventSource: SecurityComplianceCenter
        eventName: 'Potential ransomware activity'
        status: success
    condition: selection
falsepositives:
    - Unknown
level: medium

```
