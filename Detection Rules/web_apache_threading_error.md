---
title: "Apache Threading Error"
status: "test"
created: "2019/01/22"
last_modified: "2021/11/27"
tags: [initial_access, lateral_movement, t1190, t1210, detection_rule]
logsrc_product: ""
logsrc_service: "apache"
level: "medium"
---

## Apache Threading Error

### Description

Detects an issue in apache logs that reports threading related errors

```yml
title: Apache Threading Error
id: e9a2b582-3f6a-48ac-b4a1-6849cdc50b3c
status: test
description: Detects an issue in apache logs that reports threading related errors
references:
    - https://github.com/hannob/apache-uaf/blob/da40f2be3684c8095ec6066fa68eb5c07a086233/README.md
author: Florian Roth (Nextron Systems)
date: 2019/01/22
modified: 2021/11/27
tags:
    - attack.initial_access
    - attack.lateral_movement
    - attack.t1190
    - attack.t1210
logsource:
    service: apache
    definition: 'Requirements: Must be able to collect the error.log file'
detection:
    keywords:
        - '__pthread_tpp_change_priority: Assertion `new_prio == -1 || (new_prio >= fifo_min_prio && new_prio <= fifo_max_prio)'
    condition: keywords
falsepositives:
    - 3rd party apache modules - https://bz.apache.org/bugzilla/show_bug.cgi?id=46185
level: medium

```
