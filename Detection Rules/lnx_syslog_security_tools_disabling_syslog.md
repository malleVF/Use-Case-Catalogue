---
title: "Disabling Security Tools - Builtin"
status: "test"
created: "2020/06/17"
last_modified: "2022/11/26"
tags: [defense_evasion, t1562_004, detection_rule]
logsrc_product: "linux"
logsrc_service: "syslog"
level: "medium"
---

## Disabling Security Tools - Builtin

### Description

Detects disabling security tools

```yml
title: Disabling Security Tools - Builtin
id: 49f5dfc1-f92e-4d34-96fa-feba3f6acf36
related:
    - id: e3a8a052-111f-4606-9aee-f28ebeb76776
      type: derived
status: test
description: Detects disabling security tools
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.004/T1562.004.md
author: Ömer Günal, Alejandro Ortuno, oscd.community
date: 2020/06/17
modified: 2022/11/26
tags:
    - attack.defense_evasion
    - attack.t1562.004
logsource:
    product: linux
    service: syslog
detection:
    keywords:
        - 'stopping iptables'
        - 'stopping ip6tables'
        - 'stopping firewalld'
        - 'stopping cbdaemon'
        - 'stopping falcon-sensor'
    condition: keywords
falsepositives:
    - Legitimate administration activities
level: medium

```
