---
title: "Turla ComRAT"
status: "test"
created: "2020/05/26"
last_modified: "2022/08/15"
tags: [defense_evasion, command_and_control, t1071_001, g0010, detection_rule]
logsrc_product: ""
logsrc_service: ""
level: "high"
---

## Turla ComRAT

### Description

Detects Turla ComRAT patterns

```yml
title: Turla ComRAT
id: 7857f021-007f-4928-8b2c-7aedbe64bb82
status: test
description: Detects Turla ComRAT patterns
references:
    - https://www.welivesecurity.com/wp-content/uploads/2020/05/ESET_Turla_ComRAT.pdf
author: Florian Roth (Nextron Systems)
date: 2020/05/26
modified: 2022/08/15
tags:
    - attack.defense_evasion
    - attack.command_and_control
    - attack.t1071.001
    - attack.g0010
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains: '/index/index.php\?h='
    condition: selection
falsepositives:
    - Unknown
level: high

```
