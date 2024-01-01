---
title: "HybridConnectionManager Service Installation"
status: "test"
created: "2021/04/12"
last_modified: "2022/10/09"
tags: [persistence, t1554, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## HybridConnectionManager Service Installation

### Description

Rule to detect the Hybrid Connection Manager service installation.

```yml
title: HybridConnectionManager Service Installation
id: 0ee4d8a5-4e67-4faf-acfa-62a78457d1f2
status: test
description: Rule to detect the Hybrid Connection Manager service installation.
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
    service: security
    definition: The 'System Security Extension' audit subcategory need to be enabled to log the EID 4697
detection:
    selection:
        EventID: 4697
        ServiceName: HybridConnectionManager
        ServiceFileName|contains: HybridConnectionManager
    condition: selection
falsepositives:
    - Legitimate use of Hybrid Connection Manager via Azure function apps.
level: high

```
