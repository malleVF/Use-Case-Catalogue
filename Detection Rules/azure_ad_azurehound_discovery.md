---
title: "Discovery Using AzureHound"
status: "test"
created: "2022/11/27"
last_modified: ""
tags: [discovery, t1087_004, t1526, detection_rule]
logsrc_product: "azure"
logsrc_service: "signinlogs"
level: "high"
---

## Discovery Using AzureHound

### Description

Detects AzureHound (A BloodHound data collector for Microsoft Azure) activity via the default User-Agent that is used during its operation after successful authentication.

```yml
title: Discovery Using AzureHound
id: 35b781cc-1a08-4a5a-80af-42fd7c315c6b
status: test
description: Detects AzureHound (A BloodHound data collector for Microsoft Azure) activity via the default User-Agent that is used during its operation after successful authentication.
references:
    - https://github.com/BloodHoundAD/AzureHound
author: Janantha Marasinghe
date: 2022/11/27
tags:
    - attack.discovery
    - attack.t1087.004
    - attack.t1526
logsource:
    product: azure
    service: signinlogs
detection:
    selection:
        userAgent|contains: 'azurehound'
        ResultType: 0
    condition: selection
falsepositives:
    - Unknown
level: high

```
