---
title: "DiagTrackEoP Default Login Username"
status: "test"
created: "2022/08/03"
last_modified: ""
tags: [privilege_escalation, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "critical"
---

## DiagTrackEoP Default Login Username

### Description

Detects the default "UserName" used by the DiagTrackEoP POC

```yml
title: DiagTrackEoP Default Login Username
id: 2111118f-7e46-4fc8-974a-59fd8ec95196
status: test
description: Detects the default "UserName" used by the DiagTrackEoP POC
references:
    - https://github.com/Wh04m1001/DiagTrackEoP/blob/3a2fc99c9700623eb7dc7d4b5f314fd9ce5ef51f/main.cpp#L46
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/08/03
tags:
    - attack.privilege_escalation
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 9
        TargetOutboundUserName: 'thisisnotvaliduser'
    condition: selection
falsepositives:
    - Unlikely
level: critical

```
