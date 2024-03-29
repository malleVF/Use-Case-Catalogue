---
title: "Suspicious OAuth App File Download Activities"
status: "test"
created: "2021/08/23"
last_modified: "2022/10/09"
tags: [exfiltration, detection_rule]
logsrc_product: "m365"
logsrc_service: "threat_management"
level: "medium"
---

## Suspicious OAuth App File Download Activities

### Description

Detects when a Microsoft Cloud App Security reported when an app downloads multiple files from Microsoft SharePoint or Microsoft OneDrive in a manner that is unusual for the user.

```yml
title: Suspicious OAuth App File Download Activities
id: ee111937-1fe7-40f0-962a-0eb44d57d174
status: test
description: Detects when a Microsoft Cloud App Security reported when an app downloads multiple files from Microsoft SharePoint or Microsoft OneDrive in a manner that is unusual for the user.
references:
    - https://docs.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy
    - https://docs.microsoft.com/en-us/cloud-app-security/policy-template-reference
author: Austin Songer @austinsonger
date: 2021/08/23
modified: 2022/10/09
tags:
    - attack.exfiltration
logsource:
    service: threat_management
    product: m365
detection:
    selection:
        eventSource: SecurityComplianceCenter
        eventName: 'Suspicious OAuth app file download activities'
        status: success
    condition: selection
falsepositives:
    - Unknown
level: medium

```
