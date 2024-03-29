---
title: "ProcessHacker Privilege Elevation"
status: "test"
created: "2021/05/27"
last_modified: "2022/12/25"
tags: [execution, privilege_escalation, t1543_003, t1569_002, detection_rule]
logsrc_product: "windows"
logsrc_service: "system"
level: "high"
---

## ProcessHacker Privilege Elevation

### Description

Detects a ProcessHacker tool that elevated privileges to a very high level

```yml
title: ProcessHacker Privilege Elevation
id: c4ff1eac-84ad-44dd-a6fb-d56a92fc43a9
status: test
description: Detects a ProcessHacker tool that elevated privileges to a very high level
references:
    - https://twitter.com/1kwpeter/status/1397816101455765504
author: Florian Roth (Nextron Systems)
date: 2021/05/27
modified: 2022/12/25
tags:
    - attack.execution
    - attack.privilege_escalation
    - attack.t1543.003
    - attack.t1569.002
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
        ServiceName|startswith: 'ProcessHacker'
        AccountName: 'LocalSystem'
    condition: selection
falsepositives:
    - Unlikely
level: high

```
