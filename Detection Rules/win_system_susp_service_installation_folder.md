---
title: "Service Installation in Suspicious Folder"
status: "test"
created: "2022/03/18"
last_modified: "2022/10/12"
tags: [persistence, privilege_escalation, car_2013-09-005, t1543_003, detection_rule]
logsrc_product: "windows"
logsrc_service: "system"
level: "medium"
---

## Service Installation in Suspicious Folder

### Description

Detects service installation in suspicious folder appdata

```yml
title: Service Installation in Suspicious Folder
id: 5e993621-67d4-488a-b9ae-b420d08b96cb
status: test
description: Detects service installation in suspicious folder appdata
author: pH-T (Nextron Systems)
date: 2022/03/18
modified: 2022/10/12
tags:
    - attack.persistence
    - attack.privilege_escalation
    - car.2013-09-005
    - attack.t1543.003
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
    selection_suspicious1:
        ImagePath|contains:
            - '\AppData\'
            - '\\\\127.0.0.1'
            - '\\\\localhost'
    filter_zoom:
        ServiceName: 'Zoom Sharing Service'
        ImagePath|startswith: '"C:\Program Files\Common Files\Zoom\Support\CptService.exe'
    condition: all of selection* and not 1 of filter*
falsepositives:
    - Unknown
level: medium

```
