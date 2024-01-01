---
title: "Suspicious Java Children Processes"
status: "test"
created: "2022/06/03"
last_modified: ""
tags: [execution, t1059, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "high"
---

## Suspicious Java Children Processes

### Description

Detects java process spawning suspicious children

```yml
title: Suspicious Java Children Processes
id: d292e0af-9a18-420c-9525-ec0ac3936892
status: test
description: Detects java process spawning suspicious children
references:
    - https://www.tecmint.com/different-types-of-linux-shells/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/06/03
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        ParentImage|endswith: '/java'
        CommandLine|contains:
            - '/bin/sh'
            - 'bash'
            - 'dash'
            - 'ksh'
            - 'zsh'
            - 'csh'
            - 'fish'
            - 'curl'
            - 'wget'
            - 'python'
    condition: selection
falsepositives:
    - Unknown
level: high

```
