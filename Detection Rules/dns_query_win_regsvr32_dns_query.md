---
title: "DNS Query Request By Regsvr32.EXE"
status: "test"
created: "2019/10/25"
last_modified: "2023/09/18"
tags: [execution, t1559_001, defense_evasion, t1218_010, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## DNS Query Request By Regsvr32.EXE

### Description

Detects DNS queries initiated by "Regsvr32.exe"

```yml
title: DNS Query Request By Regsvr32.EXE
id: 36e037c4-c228-4866-b6a3-48eb292b9955
related:
    - id: c7e91a02-d771-4a6d-a700-42587e0b1095
      type: derived
status: test
description: Detects DNS queries initiated by "Regsvr32.exe"
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
    category: dns_query
    product: windows
detection:
    selection:
        Image|endswith: '\regsvr32.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
