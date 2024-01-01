---
title: "DNS HybridConnectionManager Service Bus"
status: "test"
created: "2021/04/12"
last_modified: "2023/01/16"
tags: [persistence, t1554, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## DNS HybridConnectionManager Service Bus

### Description

Detects Azure Hybrid Connection Manager services querying the Azure service bus service

```yml
title: DNS HybridConnectionManager Service Bus
id: 7bd3902d-8b8b-4dd4-838a-c6862d40150d
status: test
description: Detects Azure Hybrid Connection Manager services querying the Azure service bus service
references:
    - https://twitter.com/Cyb3rWard0g/status/1381642789369286662
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
date: 2021/04/12
modified: 2023/01/16
tags:
    - attack.persistence
    - attack.t1554
logsource:
    product: windows
    category: dns_query
detection:
    selection:
        QueryName|contains: 'servicebus.windows.net'
        Image|contains: 'HybridConnectionManager'
    condition: selection
falsepositives:
    - Legitimate use of Azure Hybrid Connection Manager and the Azure Service Bus service
level: high

```
