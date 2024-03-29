---
title: "Suspicious Inbox Forwarding"
status: "test"
created: "2021/08/22"
last_modified: "2022/10/09"
tags: [exfiltration, t1020, detection_rule]
logsrc_product: "m365"
logsrc_service: "threat_management"
level: "low"
---

## Suspicious Inbox Forwarding

### Description

Detects when a Microsoft Cloud App Security reported suspicious email forwarding rules, for example, if a user created an inbox rule that forwards a copy of all emails to an external address.

```yml
title: Suspicious Inbox Forwarding
id: 6c220477-0b5b-4b25-bb90-66183b4089e8
status: test
description: Detects when a Microsoft Cloud App Security reported suspicious email forwarding rules, for example, if a user created an inbox rule that forwards a copy of all emails to an external address.
references:
    - https://docs.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy
    - https://docs.microsoft.com/en-us/cloud-app-security/policy-template-reference
author: Austin Songer @austinsonger
date: 2021/08/22
modified: 2022/10/09
tags:
    - attack.exfiltration
    - attack.t1020
logsource:
    service: threat_management
    product: m365
detection:
    selection:
        eventSource: SecurityComplianceCenter
        eventName: 'Suspicious inbox forwarding'
        status: success
    condition: selection
falsepositives:
    - Unknown
level: low

```
