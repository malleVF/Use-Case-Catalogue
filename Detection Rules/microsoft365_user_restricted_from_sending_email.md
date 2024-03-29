---
title: "Microsoft 365 - User Restricted from Sending Email"
status: "test"
created: "2021/08/19"
last_modified: "2022/10/09"
tags: [initial_access, t1199, detection_rule]
logsrc_product: "m365"
logsrc_service: "threat_management"
level: "medium"
---

## Microsoft 365 - User Restricted from Sending Email

### Description

Detects when a Security Compliance Center reported a user who exceeded sending limits of the service policies and because of this has been restricted from sending email.

```yml
title: Microsoft 365 - User Restricted from Sending Email
id: ff246f56-7f24-402a-baca-b86540e3925c
status: test
description: Detects when a Security Compliance Center reported a user who exceeded sending limits of the service policies and because of this has been restricted from sending email.
references:
    - https://docs.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy
    - https://docs.microsoft.com/en-us/cloud-app-security/policy-template-reference
author: austinsonger
date: 2021/08/19
modified: 2022/10/09
tags:
    - attack.initial_access
    - attack.t1199
logsource:
    service: threat_management
    product: m365
detection:
    selection:
        eventSource: SecurityComplianceCenter
        eventName: 'User restricted from sending email'
        status: success
    condition: selection
falsepositives:
    - Unknown
level: medium

```
