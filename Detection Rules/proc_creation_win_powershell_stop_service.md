---
title: "Stop Windows Service Via PowerShell Stop-Service"
status: "experimental"
created: "2023/03/05"
last_modified: ""
tags: [impact, t1489, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "low"
---

## Stop Windows Service Via PowerShell Stop-Service

### Description

Detects the stopping of a Windows service

```yml
title: Stop Windows Service Via PowerShell Stop-Service
id: c49c5062-0966-4170-9efd-9968c913a6cf
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
    selection_sc_net_img:
        - OriginalFileName:
              - 'PowerShell.EXE'
              - 'pwsh.dll'
        - Image|endswith:
              - '\powershell.exe'
              - '\pwsh.exe'
    selection_cli:
        CommandLine|contains: 'Stop-Service '
    condition: all of selection_*
falsepositives:
    - There are many legitimate reasons to stop a service. This rule isn't looking for any suspicious behaviour in particular. Filter legitimate activity accordingly
level: low

```
