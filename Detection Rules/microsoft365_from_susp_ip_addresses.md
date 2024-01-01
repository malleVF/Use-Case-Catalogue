---
title: "Activity from Suspicious IP Addresses"
status: "test"
created: "2021/08/23"
last_modified: "2022/10/09"
tags: [command_and_control, t1573, detection_rule]
logsrc_product: "m365"
logsrc_service: "threat_detection"
level: "medium"
---

## Activity from Suspicious IP Addresses

### Description

Detects when a Microsoft Cloud App Security reported users were active from an IP address identified as risky by Microsoft Threat Intelligence.
These IP addresses are involved in malicious activities, such as Botnet C&C, and may indicate compromised account.


```yml
title: Activity from Suspicious IP Addresses
id: a3501e8e-af9e-43c6-8cd6-9360bdaae498
status: test
description: |
  Detects when a Microsoft Cloud App Security reported users were active from an IP address identified as risky by Microsoft Threat Intelligence.
  These IP addresses are involved in malicious activities, such as Botnet C&C, and may indicate compromised account.
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
    service: threat_detection
    product: m365
detection:
    selection:
        eventSource: SecurityComplianceCenter
        eventName: 'Activity from suspicious IP addresses'
        status: success
    condition: selection
falsepositives:
    - Unknown
level: medium

```
