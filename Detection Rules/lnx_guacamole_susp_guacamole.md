---
title: "Guacamole Two Users Sharing Session Anomaly"
status: "test"
created: "2020/07/03"
last_modified: "2021/11/27"
tags: [credential_access, t1212, detection_rule]
logsrc_product: "linux"
logsrc_service: "guacamole"
level: "high"
---

## Guacamole Two Users Sharing Session Anomaly

### Description

Detects suspicious session with two users present

```yml
title: Guacamole Two Users Sharing Session Anomaly
id: 1edd77db-0669-4fef-9598-165bda82826d
status: test
description: Detects suspicious session with two users present
references:
    - https://research.checkpoint.com/2020/apache-guacamole-rce/
author: Florian Roth (Nextron Systems)
date: 2020/07/03
modified: 2021/11/27
tags:
    - attack.credential_access
    - attack.t1212
logsource:
    product: linux
    service: guacamole
detection:
    selection:
        - '(2 users now present)'
    condition: selection
falsepositives:
    - Unknown
level: high

```
