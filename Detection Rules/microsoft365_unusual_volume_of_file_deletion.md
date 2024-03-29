---
title: "Microsoft 365 - Unusual Volume of File Deletion"
status: "test"
created: "2021/08/19"
last_modified: "2022/10/09"
tags: [impact, t1485, detection_rule]
logsrc_product: "m365"
logsrc_service: "threat_management"
level: "medium"
---

## Microsoft 365 - Unusual Volume of File Deletion

### Description

Detects when a Microsoft Cloud App Security reported a user has deleted a unusual a large volume of files.

```yml
title: Microsoft 365 - Unusual Volume of File Deletion
id: 78a34b67-3c39-4886-8fb4-61c46dc18ecd
status: test
description: Detects when a Microsoft Cloud App Security reported a user has deleted a unusual a large volume of files.
references:
    - https://docs.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy
    - https://docs.microsoft.com/en-us/cloud-app-security/policy-template-reference
author: austinsonger
date: 2021/08/19
modified: 2022/10/09
tags:
    - attack.impact
    - attack.t1485
logsource:
    service: threat_management
    product: m365
detection:
    selection:
        eventSource: SecurityComplianceCenter
        eventName: 'Unusual volume of file deletion'
        status: success
    condition: selection
falsepositives:
    - Unknown
level: medium

```
