---
title: "BabyShark Agent Pattern"
status: "test"
created: "2021/06/09"
last_modified: "2022/08/15"
tags: [command_and_control, t1071_001, detection_rule]
logsrc_product: ""
logsrc_service: ""
level: "critical"
---

## BabyShark Agent Pattern

### Description

Detects Baby Shark C2 Framework communication patterns

```yml
title: BabyShark Agent Pattern
id: 304810ed-8853-437f-9e36-c4975c3dfd7e
status: test
description: Detects Baby Shark C2 Framework communication patterns
references:
    - https://nasbench.medium.com/understanding-detecting-c2-frameworks-babyshark-641be4595845
author: Florian Roth (Nextron Systems)
date: 2021/06/09
modified: 2022/08/15
tags:
    - attack.command_and_control
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains: 'momyshark\?key='
    condition: selection
falsepositives:
    - Unknown
level: critical

```
