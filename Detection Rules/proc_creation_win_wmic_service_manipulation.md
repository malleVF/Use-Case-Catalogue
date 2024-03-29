---
title: "Service Started/Stopped Via Wmic.EXE"
status: "experimental"
created: "2022/06/20"
last_modified: "2023/02/14"
tags: [execution, t1047, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Service Started/Stopped Via Wmic.EXE

### Description

Detects usage of wmic to start or stop a service

```yml
title: Service Started/Stopped Via Wmic.EXE
id: 0b7163dc-7eee-4960-af17-c0cd517f92da
status: experimental
description: Detects usage of wmic to start or stop a service
references:
    - https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/06/20
modified: 2023/02/14
tags:
    - attack.execution
    - attack.t1047
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - OriginalFileName: 'wmic.exe'
        - Image|endswith: '\WMIC.exe'
    selection_cli:
        CommandLine|contains|all:
            - ' service '
            - ' call '
        CommandLine|contains:
            - 'stopservice'
            - 'startservice'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium

```
