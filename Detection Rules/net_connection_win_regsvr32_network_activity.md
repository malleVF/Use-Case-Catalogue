---
title: "Network Connection Initiated By Regsvr32.EXE"
status: "test"
created: "2019/10/25"
last_modified: "2023/09/18"
tags: [execution, t1559_001, defense_evasion, t1218_010, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Network Connection Initiated By Regsvr32.EXE

### Description

Detects network connections initiated by Regsvr32.exe

```yml
title: Network Connection Initiated By Regsvr32.EXE
id: c7e91a02-d771-4a6d-a700-42587e0b1095
status: test
description: Detects network connections initiated by Regsvr32.exe
references:
    - https://pentestlab.blog/2017/05/11/applocker-bypass-regsvr32/
    - https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/
author: Dmitriy Lifanov, oscd.community
date: 2019/10/25
modified: 2023/09/18
tags:
    - attack.execution
    - attack.t1559.001
    - attack.defense_evasion
    - attack.t1218.010
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Initiated: 'true'
        Image|endswith: '\regsvr32.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
