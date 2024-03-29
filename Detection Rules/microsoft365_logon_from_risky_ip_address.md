---
title: "Logon from a Risky IP Address"
status: "test"
created: "2021/08/23"
last_modified: "2022/10/09"
tags: [initial_access, t1078, detection_rule]
logsrc_product: "m365"
logsrc_service: "threat_management"
level: "medium"
---

## Logon from a Risky IP Address

### Description

Detects when a Microsoft Cloud App Security reported when a user signs into your sanctioned apps from a risky IP address.

```yml
title: Logon from a Risky IP Address
id: c191e2fa-f9d6-4ccf-82af-4f2aba08359f
status: test
description: Detects when a Microsoft Cloud App Security reported when a user signs into your sanctioned apps from a risky IP address.
references:
    - https://docs.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy
    - https://docs.microsoft.com/en-us/cloud-app-security/policy-template-reference
author: Austin Songer @austinsonger
date: 2021/08/23
modified: 2022/10/09
tags:
    - attack.initial_access
    - attack.t1078
logsource:
    service: threat_management
    product: m365
detection:
    selection:
        eventSource: SecurityComplianceCenter
        eventName: 'Log on from a risky IP address'
        status: success
    condition: selection
falsepositives:
    - Unknown
level: medium

```
