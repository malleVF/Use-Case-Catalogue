---
title: "HybridConnectionManager Service Running"
status: "test"
created: "2021/04/12"
last_modified: "2022/10/09"
tags: [persistence, t1554, detection_rule]
logsrc_product: "windows"
logsrc_service: "microsoft-servicebus-client"
level: "high"
---

## HybridConnectionManager Service Running

### Description

Rule to detect the Hybrid Connection Manager service running on an endpoint.

```yml
title: HybridConnectionManager Service Running
id: b55d23e5-6821-44ff-8a6e-67218891e49f
status: test
description: Rule to detect the Hybrid Connection Manager service running on an endpoint.
references:
    - https://twitter.com/Cyb3rWard0g/status/1381642789369286662
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
date: 2021/04/12
modified: 2022/10/09
tags:
    - attack.persistence
    - attack.t1554
logsource:
    product: windows
    service: microsoft-servicebus-client
detection:
    selection:
        EventID:
            - 40300
            - 40301
            - 40302
    keywords:
        - 'HybridConnection'
        - 'sb://'
        - 'servicebus.windows.net'
        - 'HybridConnectionManage'
    condition: selection and keywords
falsepositives:
    - Legitimate use of Hybrid Connection Manager via Azure function apps.
level: high

```
