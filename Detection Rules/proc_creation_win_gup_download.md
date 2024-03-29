---
title: "File Download Using Notepad++ GUP Utility"
status: "experimental"
created: "2022/06/10"
last_modified: "2023/03/02"
tags: [command_and_control, t1105, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## File Download Using Notepad++ GUP Utility

### Description

Detects execution of the Notepad++ updater (gup) from a process other than Notepad++ to download files.

```yml
title: File Download Using Notepad++ GUP Utility
id: 44143844-0631-49ab-97a0-96387d6b2d7c
status: experimental
description: Detects execution of the Notepad++ updater (gup) from a process other than Notepad++ to download files.
references:
    - https://twitter.com/nas_bench/status/1535322182863179776
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/06/10
modified: 2023/03/02
tags:
    - attack.command_and_control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\GUP.exe'
        - OriginalFileName: 'gup.exe'
    selection_cli:
        CommandLine|contains|all:
            - ' -unzipTo '
            - 'http'
    filter:
        ParentImage|endswith: '\notepad++.exe'
    condition: all of selection* and not filter
falsepositives:
    - Other parent processes other than notepad++ using GUP that are not currently identified
level: high

```
