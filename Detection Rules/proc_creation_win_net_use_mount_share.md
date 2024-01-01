---
title: "Windows Share Mount Via Net.EXE"
status: "experimental"
created: "2023/02/02"
last_modified: "2023/02/21"
tags: [lateral_movement, t1021_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "low"
---

## Windows Share Mount Via Net.EXE

### Description

Detects when a share is mounted using the "net.exe" utility

```yml
title: Windows Share Mount Via Net.EXE
id: f117933c-980c-4f78-b384-e3d838111165
related:
    - id: 3abd6094-7027-475f-9630-8ab9be7b9725
      type: similar
status: experimental
description: Detects when a share is mounted using the "net.exe" utility
references:
    - https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/02/02
modified: 2023/02/21
tags:
    - attack.lateral_movement
    - attack.t1021.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\net.exe'
              - '\net1.exe'
        - OriginalFileName:
              - 'net.exe'
              - 'net1.exe'
    selection_cli:
        CommandLine|contains:
            - ' use '
            - ' \\\\'
    condition: all of selection_*
falsepositives:
    - Legitimate activity by administrators and scripts
level: low

```