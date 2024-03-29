---
title: "Exfiltration and Tunneling Tools Execution"
status: "test"
created: "2019/10/24"
last_modified: "2021/11/27"
tags: [exfiltration, command_and_control, t1041, t1572, t1071_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Exfiltration and Tunneling Tools Execution

### Description

Execution of well known tools for data exfiltration and tunneling

```yml
title: Exfiltration and Tunneling Tools Execution
id: c75309a3-59f8-4a8d-9c2c-4c927ad50555
status: test
description: Execution of well known tools for data exfiltration and tunneling
author: Daniil Yugoslavskiy, oscd.community
date: 2019/10/24
modified: 2021/11/27
tags:
    - attack.exfiltration
    - attack.command_and_control
    - attack.t1041
    - attack.t1572
    - attack.t1071.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\plink.exe'
            - '\socat.exe'
            - '\stunnel.exe'
            - '\httptunnel.exe'
    condition: selection
falsepositives:
    - Legitimate Administrator using tools
level: medium

```
