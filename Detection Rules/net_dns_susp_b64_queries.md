---
title: "Suspicious DNS Query with B64 Encoded String"
status: "test"
created: "2018/05/10"
last_modified: "2022/10/09"
tags: [exfiltration, t1048_003, command_and_control, t1071_004, detection_rule]
logsrc_product: ""
logsrc_service: ""
level: "medium"
---

## Suspicious DNS Query with B64 Encoded String

### Description

Detects suspicious DNS queries using base64 encoding

```yml
title: Suspicious DNS Query with B64 Encoded String
id: 4153a907-2451-4e4f-a578-c52bb6881432
status: test
description: Detects suspicious DNS queries using base64 encoding
references:
    - https://github.com/krmaxwell/dns-exfiltration
author: Florian Roth (Nextron Systems)
date: 2018/05/10
modified: 2022/10/09
tags:
    - attack.exfiltration
    - attack.t1048.003
    - attack.command_and_control
    - attack.t1071.004
logsource:
    category: dns
detection:
    selection:
        query|contains: '==.'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
