---
title: "iOS Implant URL Pattern"
status: "test"
created: "2019/08/30"
last_modified: "2022/08/15"
tags: [execution, t1203, collection, t1005, t1119, credential_access, t1528, t1552_001, detection_rule]
logsrc_product: ""
logsrc_service: ""
level: "critical"
---

## iOS Implant URL Pattern

### Description

Detects URL pattern used by iOS Implant

```yml
title: iOS Implant URL Pattern
id: e06ac91d-b9e6-443d-8e5b-af749e7aa6b6
status: test
description: Detects URL pattern used by iOS Implant
references:
    - https://googleprojectzero.blogspot.com/2019/08/implant-teardown.html
    - https://twitter.com/craiu/status/1167358457344925696
author: Florian Roth (Nextron Systems)
date: 2019/08/30
modified: 2022/08/15
tags:
    - attack.execution
    - attack.t1203
    - attack.collection
    - attack.t1005
    - attack.t1119
    - attack.credential_access
    - attack.t1528
    - attack.t1552.001
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains: '/list/suc\?name='
    condition: selection
fields:
    - ClientIP
    - c-uri
    - c-useragent
falsepositives:
    - Unknown
level: critical

```
