---
title: "Sign-ins from Non-Compliant Devices"
status: "test"
created: "2022/06/28"
last_modified: ""
tags: [defense_evasion, t1078_004, detection_rule]
logsrc_product: "azure"
logsrc_service: "signinlogs"
level: "high"
---

## Sign-ins from Non-Compliant Devices

### Description

Monitor and alert for sign-ins where the device was non-compliant.

```yml
title: Sign-ins from Non-Compliant Devices
id: 4f77e1d7-3982-4ee0-8489-abf2d6b75284
status: test
description: Monitor and alert for sign-ins where the device was non-compliant.
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-devices#non-compliant-device-sign-in
author: Michael Epping, '@mepples21'
date: 2022/06/28
tags:
    - attack.defense_evasion
    - attack.t1078.004
logsource:
    product: azure
    service: signinlogs
detection:
    selection:
        DeviceDetail.isCompliant: 'false'
    condition: selection
falsepositives:
    - Unknown
level: high

```
