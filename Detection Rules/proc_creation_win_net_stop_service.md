---
title: "Stop Windows Service Via Net.EXE"
status: "experimental"
created: "2023/03/05"
last_modified: ""
tags: [impact, t1489, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "low"
---

## Stop Windows Service Via Net.EXE

### Description

Detects the stopping of a Windows service

```yml
title: Stop Windows Service Via Net.EXE
id: 88872991-7445-4a22-90b2-a3adadb0e827
related:
    - id: eb87818d-db5d-49cc-a987-d5da331fbd90
      type: obsoletes
status: experimental
description: Detects the stopping of a Windows service
author: Jakob Weinzettl, oscd.community, Nasreddine Bencherchali (Nextron Systems)
date: 2023/03/05
tags:
    - attack.impact
    - attack.t1489
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - OriginalFileName:
              - 'net.exe'
              - 'net1.exe'
        - Image|endswith:
              - '\net.exe'
              - '\net1.exe'
    selection_cli:
        CommandLine|contains: ' stop '
    condition: all of selection_*
falsepositives:
    - There are many legitimate reasons to stop a service. This rule isn't looking for any suspicious behaviour in particular. Filter legitimate activity accordingly
level: low

```
