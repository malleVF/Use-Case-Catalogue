---
title: "PwnDrp Access"
status: "test"
created: "2020/04/15"
last_modified: "2021/11/27"
tags: [command_and_control, t1071_001, t1102_001, t1102_003, detection_rule]
logsrc_product: ""
logsrc_service: ""
level: "critical"
---

## PwnDrp Access

### Description

Detects downloads from PwnDrp web servers developed for red team testing and most likely also used for criminal activity

```yml
title: PwnDrp Access
id: 2b1ee7e4-89b6-4739-b7bb-b811b6607e5e
status: test
description: Detects downloads from PwnDrp web servers developed for red team testing and most likely also used for criminal activity
references:
    - https://breakdev.org/pwndrop/
author: Florian Roth (Nextron Systems)
date: 2020/04/15
modified: 2021/11/27
tags:
    - attack.command_and_control
    - attack.t1071.001
    - attack.t1102.001
    - attack.t1102.003
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains: '/pwndrop/'
    condition: selection
fields:
    - ClientIP
    - c-uri
    - c-useragent
falsepositives:
    - Unknown
level: critical

```
