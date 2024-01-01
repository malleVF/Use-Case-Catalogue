---
title: "Windows Internet Hosted WebDav Share Mount Via Net.EXE"
status: "experimental"
created: "2023/02/21"
last_modified: "2023/07/25"
tags: [lateral_movement, t1021_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Windows Internet Hosted WebDav Share Mount Via Net.EXE

### Description

Detects when an internet hosted webdav share is mounted using the "net.exe" utility

```yml
title: Windows Internet Hosted WebDav Share Mount Via Net.EXE
id: 7e6237fe-3ddb-438f-9381-9bf9de5af8d0
status: experimental
description: Detects when an internet hosted webdav share is mounted using the "net.exe" utility
references:
    - https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/02/21
modified: 2023/07/25
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
        CommandLine|contains|all:
            - ' use '
            - ' http'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high

```
