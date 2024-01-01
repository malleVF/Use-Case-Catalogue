---
title: "Potential EventLog File Location Tampering"
status: "experimental"
created: "2023/01/02"
last_modified: "2023/08/17"
tags: [defense_evasion, t1562_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Potential EventLog File Location Tampering

### Description

Detects tampering with EventLog service "file" key. In order to change the default location of an Evtx file. This technique is used to tamper with log collection and alerting

```yml
title: Potential EventLog File Location Tampering
id: 0cb8d736-995d-4ce7-a31e-1e8d452a1459
status: experimental
description: Detects tampering with EventLog service "file" key. In order to change the default location of an Evtx file. This technique is used to tamper with log collection and alerting
references:
    - https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key
author: D3F7A5105
date: 2023/01/02
modified: 2023/08/17
tags:
    - attack.defense_evasion
    - attack.t1562.002
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\SYSTEM\CurrentControlSet\Services\EventLog\'
        TargetObject|endswith: '\File'
    filter:
        Details|contains: '\System32\Winevt\Logs\'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high

```