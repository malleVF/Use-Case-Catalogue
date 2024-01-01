---
title: "HybridConnectionManager Service Installation - Registry"
status: "test"
created: "2021/04/12"
last_modified: "2022/11/27"
tags: [resource_development, t1608, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## HybridConnectionManager Service Installation - Registry

### Description

Detects the installation of the Azure Hybrid Connection Manager service to allow remote code execution from Azure function.

```yml
title: HybridConnectionManager Service Installation - Registry
id: ac8866c7-ce44-46fd-8c17-b24acff96ca8
status: test
description: Detects the installation of the Azure Hybrid Connection Manager service to allow remote code execution from Azure function.
references:
    - https://twitter.com/Cyb3rWard0g/status/1381642789369286662
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
date: 2021/04/12
modified: 2022/11/27
tags:
    - attack.resource_development
    - attack.t1608
logsource:
    category: registry_event
    product: windows
detection:
    selection1:
        TargetObject|contains: '\Services\HybridConnectionManager'
    selection2:
        EventType: SetValue
        Details|contains: 'Microsoft.HybridConnectionManager.Listener.exe'
    condition: selection1 or selection2
falsepositives:
    - Unknown
level: high

```
