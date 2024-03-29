---
title: "Cobalt Strike DNS Beaconing"
status: "test"
created: "2018/05/10"
last_modified: "2022/10/09"
tags: [command_and_control, t1071_004, detection_rule]
logsrc_product: ""
logsrc_service: ""
level: "critical"
---

## Cobalt Strike DNS Beaconing

### Description

Detects suspicious DNS queries known from Cobalt Strike beacons

```yml
title: Cobalt Strike DNS Beaconing
id: 2975af79-28c4-4d2f-a951-9095f229df29
status: test
description: Detects suspicious DNS queries known from Cobalt Strike beacons
references:
    - https://www.icebrg.io/blog/footprints-of-fin7-tracking-actor-patterns
    - https://www.sekoia.io/en/hunting-and-detecting-cobalt-strike/
author: Florian Roth (Nextron Systems)
date: 2018/05/10
modified: 2022/10/09
tags:
    - attack.command_and_control
    - attack.t1071.004
logsource:
    category: dns
detection:
    selection1:
        query|startswith:
            - 'aaa.stage.'
            - 'post.1'
    selection2:
        query|contains: '.stage.123456.'
    condition: 1 of selection*
falsepositives:
    - Unknown
level: critical

```
