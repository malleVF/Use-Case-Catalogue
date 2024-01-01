---
title: "Potential Discovery Activity Using Find - Linux"
status: "test"
created: "2022/12/28"
last_modified: ""
tags: [discovery, t1083, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "medium"
---

## Potential Discovery Activity Using Find - Linux

### Description

Detects usage of "find" binary in a suspicious manner to perform discovery

```yml
title: Potential Discovery Activity Using Find - Linux
id: 8344c0e5-5783-47cc-9cf9-a0f7fd03e6cf
related:
    - id: 85de3a19-b675-4a51-bfc6-b11a5186c971
      type: similar
status: test
description: Detects usage of "find" binary in a suspicious manner to perform discovery
references:
    - https://github.com/SaiSathvik1/Linux-Privilege-Escalation-Notes
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/12/28
tags:
    - attack.discovery
    - attack.t1083
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/find'
        CommandLine|contains:
            - '-perm -4000'
            - '-perm -2000'
            - '-perm 0777'
            - '-perm -222'
            - '-perm -o w'
            - '-perm -o x'
            - '-perm -u=s'
            - '-perm -g=s'
    condition: selection
falsepositives:
    - Unknown
level: medium

```