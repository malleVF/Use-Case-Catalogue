---
title: "NTLM Logon"
status: "test"
created: "2018/06/08"
last_modified: "2022/10/05"
tags: [lateral_movement, t1550_002, detection_rule]
logsrc_product: "windows"
logsrc_service: "ntlm"
level: "low"
---

## NTLM Logon

### Description

Detects logons using NTLM, which could be caused by a legacy source or attackers

```yml
title: NTLM Logon
id: 98c3bcf1-56f2-49dc-9d8d-c66cf190238b
status: test
description: Detects logons using NTLM, which could be caused by a legacy source or attackers
references:
    - https://twitter.com/JohnLaTwC/status/1004895028995477505
    - https://goo.gl/PsqrhT
author: Florian Roth (Nextron Systems)
date: 2018/06/08
modified: 2022/10/05
tags:
    - attack.lateral_movement
    - attack.t1550.002
logsource:
    product: windows
    service: ntlm
    definition: Requires events from Microsoft-Windows-NTLM/Operational
detection:
    selection:
        EventID: 8002
        ProcessName|contains: '*'  # We use this to avoid false positives with ID 8002 on other log sources if the logsource isn't set correctly
    condition: selection
falsepositives:
    - Legacy hosts
level: low

```
