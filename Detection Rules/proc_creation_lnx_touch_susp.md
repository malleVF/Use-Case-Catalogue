---
title: "Touch Suspicious Service File"
status: "test"
created: "2023/01/11"
last_modified: ""
tags: [defense_evasion, t1070_006, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "medium"
---

## Touch Suspicious Service File

### Description

Detects usage of the "touch" process in service file.

```yml
title: Touch Suspicious Service File
id: 31545105-3444-4584-bebf-c466353230d2
status: test
description: Detects usage of the "touch" process in service file.
references:
    - https://blogs.blackberry.com/
    - https://twitter.com/Joseliyo_Jstnk/status/1620131033474822144
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: 2023/01/11
tags:
    - attack.defense_evasion
    - attack.t1070.006
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/touch'
        CommandLine|contains: ' -t '
        CommandLine|endswith: '.service'
    condition: selection
falsepositives:
    - Admin changing date of files.
level: medium

```
