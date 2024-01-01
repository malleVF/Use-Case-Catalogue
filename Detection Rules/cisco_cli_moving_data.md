---
title: "Cisco Stage Data"
status: "test"
created: "2019/08/12"
last_modified: "2023/01/04"
tags: [collection, lateral_movement, command_and_control, exfiltration, t1074, t1105, t1560_001, detection_rule]
logsrc_product: "cisco"
logsrc_service: "aaa"
level: "low"
---

## Cisco Stage Data

### Description

Various protocols maybe used to put data on the device for exfil or infil

```yml
title: Cisco Stage Data
id: 5e51acb2-bcbe-435b-99c6-0e3cd5e2aa59
status: test
description: Various protocols maybe used to put data on the device for exfil or infil
author: Austin Clark
date: 2019/08/12
modified: 2023/01/04
tags:
    - attack.collection
    - attack.lateral_movement
    - attack.command_and_control
    - attack.exfiltration
    - attack.t1074
    - attack.t1105
    - attack.t1560.001
logsource:
    product: cisco
    service: aaa
detection:
    keywords:
        - 'tftp'
        - 'rcp'
        - 'puts'
        - 'copy'
        - 'configure replace'
        - 'archive tar'
    condition: keywords
fields:
    - CmdSet
falsepositives:
    - Generally used to copy configs or IOS images
level: low

```
