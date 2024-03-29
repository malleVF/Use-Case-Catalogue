---
title: "Bitsadmin to Uncommon IP Server Address"
status: "test"
created: "2022/06/10"
last_modified: "2022/08/24"
tags: [command_and_control, t1071_001, defense_evasion, persistence, t1197, s0190, detection_rule]
logsrc_product: ""
logsrc_service: ""
level: "high"
---

## Bitsadmin to Uncommon IP Server Address

### Description

Detects Bitsadmin connections to IP addresses instead of FQDN names

```yml
title: Bitsadmin to Uncommon IP Server Address
id: 8ccd35a2-1c7c-468b-b568-ac6cdf80eec3
status: test
description: Detects Bitsadmin connections to IP addresses instead of FQDN names
author: Florian Roth (Nextron Systems)
date: 2022/06/10
modified: 2022/08/24
tags:
    - attack.command_and_control
    - attack.t1071.001
    - attack.defense_evasion
    - attack.persistence
    - attack.t1197
    - attack.s0190
logsource:
    category: proxy
detection:
    selection:
        c-useragent|startswith: 'Microsoft BITS/'
        cs-host|endswith:
            - '1'
            - '2'
            - '3'
            - '4'
            - '5'
            - '6'
            - '7'
            - '8'
            - '9'
    condition: selection
falsepositives:
    - Unknown
level: high

```
