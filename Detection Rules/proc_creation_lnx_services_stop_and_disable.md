---
title: "Disable Or Stop Services"
status: "test"
created: "2022/09/15"
last_modified: ""
tags: [defense_evasion, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "medium"
---

## Disable Or Stop Services

### Description

Detects the usage of utilities such as 'systemctl', 'service'...etc to stop or disable tools and services

```yml
title: Disable Or Stop Services
id: de25eeb8-3655-4643-ac3a-b662d3f26b6b
status: test
description: Detects the usage of utilities such as 'systemctl', 'service'...etc to stop or disable tools and services
references:
    - https://www.trendmicro.com/pl_pl/research/20/i/the-evolution-of-malicious-shell-scripts.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/09/15
tags:
    - attack.defense_evasion
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith:
            - '/service'
            - '/systemctl'
            - '/chkconfig'
        CommandLine|contains:
            - 'stop'
            - 'disable'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: medium

```
