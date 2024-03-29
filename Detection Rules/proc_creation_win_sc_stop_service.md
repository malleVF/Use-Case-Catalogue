---
title: "Stop Windows Service Via Sc.EXE"
status: "experimental"
created: "2023/03/05"
last_modified: ""
tags: [impact, t1489, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "low"
---

## Stop Windows Service Via Sc.EXE

### Description

Detects the stopping of a Windows service

```yml
title: Stop Windows Service Via Sc.EXE
id: 81bcb81b-5b1f-474b-b373-52c871aaa7b1
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
        - OriginalFileName: 'sc.exe'
        - Image|endswith: '\sc.exe'
    selection_cli:
        CommandLine|contains: ' stop '
    filter_kaspersky:
        CommandLine:
            - 'sc  stop KSCWebConsoleMessageQueue' # kaspersky Security Center Web Console double space between sc and stop
            - 'sc  stop LGHUBUpdaterService' # Logitech LGHUB Updater Service
        User|contains: # covers many language settings
            - 'AUTHORI'
            - 'AUTORI'
    condition: all of selection_* and not 1 of filter_*
falsepositives:
    - There are many legitimate reasons to stop a service. This rule isn't looking for any suspicious behaviour in particular. Filter legitimate activity accordingly
level: low

```
