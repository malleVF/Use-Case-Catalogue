---
title: "Disabled MFA to Bypass Authentication Mechanisms"
status: "test"
created: "2022/02/08"
last_modified: ""
tags: [persistence, t1556, detection_rule]
logsrc_product: "azure"
logsrc_service: "activitylogs"
level: "medium"
---

## Disabled MFA to Bypass Authentication Mechanisms

### Description

Detection for when multi factor authentication has been disabled, which might indicate a malicious activity to bypass authentication mechanisms.

```yml
title: Disabled MFA to Bypass Authentication Mechanisms
id: 7ea78478-a4f9-42a6-9dcd-f861816122bf
status: test
description: Detection for when multi factor authentication has been disabled, which might indicate a malicious activity to bypass authentication mechanisms.
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-userstates
author: '@ionsor'
date: 2022/02/08
tags:
    - attack.persistence
    - attack.t1556
logsource:
    product: azure
    service: activitylogs
detection:
    selection:
        eventSource: AzureActiveDirectory
        eventName: 'Disable Strong Authentication.'
        status: success
    condition: selection
falsepositives:
    - Authorized modification by administrators
level: medium

```
