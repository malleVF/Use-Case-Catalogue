---
title: "Remote Access Tool - ScreenConnect Suspicious Execution"
status: "test"
created: "2021/02/11"
last_modified: "2023/03/05"
tags: [initial_access, t1133, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Remote Access Tool - ScreenConnect Suspicious Execution

### Description

Detects ScreenConnect program starts that establish a remote access to that system (not meeting, not remote support)

```yml
title: Remote Access Tool - ScreenConnect Suspicious Execution
id: 75bfe6e6-cd8e-429e-91d3-03921e1d7962
status: test
description: Detects ScreenConnect program starts that establish a remote access to that system (not meeting, not remote support)
references:
    - https://www.anomali.com/blog/probable-iranian-cyber-actors-static-kitten-conducting-cyberespionage-campaign-targeting-uae-and-kuwait-government-agencies
author: Florian Roth (Nextron Systems)
date: 2021/02/11
modified: 2023/03/05
tags:
    - attack.initial_access
    - attack.t1133
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'e=Access&'
            - 'y=Guest&'
            - '&p='
            - '&c='
            - '&k='
    condition: selection
falsepositives:
    - Legitimate use by administrative staff
level: high

```
