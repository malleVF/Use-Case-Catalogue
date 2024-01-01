---
title: "Port Forwarding Activity Via SSH.EXE"
status: "experimental"
created: "2022/10/12"
last_modified: "2023/11/06"
tags: [command_and_control, lateral_movement, t1572, t1021_001, t1021_004, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Port Forwarding Activity Via SSH.EXE

### Description

Detects port forwarding activity via SSH.exe

```yml
title: Port Forwarding Activity Via SSH.EXE
id: 327f48c1-a6db-4eb8-875a-f6981f1b0183
status: experimental
description: Detects port forwarding activity via SSH.exe
references:
    - https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/10/12
modified: 2023/11/06
tags:
    - attack.command_and_control
    - attack.lateral_movement
    - attack.t1572
    - attack.t1021.001
    - attack.t1021.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\ssh.exe'
        CommandLine|contains:
            - ' -R '
            - ' /R '
    condition: selection
falsepositives:
    - Administrative activity using a remote port forwarding to a local port
level: medium

```
