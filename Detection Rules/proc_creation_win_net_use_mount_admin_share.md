---
title: "Windows Admin Share Mount Via Net.EXE"
status: "test"
created: "2020/10/05"
last_modified: "2023/02/21"
tags: [lateral_movement, t1021_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Windows Admin Share Mount Via Net.EXE

### Description

Detects when an admin share is mounted using net.exe

```yml
title: Windows Admin Share Mount Via Net.EXE
id: 3abd6094-7027-475f-9630-8ab9be7b9725
related:
    - id: f117933c-980c-4f78-b384-e3d838111165
      type: similar
status: test
description: Detects when an admin share is mounted using net.exe
references:
    - https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view
author: oscd.community, Teymur Kheirkhabarov @HeirhabarovT, Zach Stanford @svch0st, wagga
date: 2020/10/05
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
        CommandLine|contains|all:
            - ' use '
            - ' \\\\*\\*$'
    condition: all of selection_*
falsepositives:
    - Administrators
level: medium

```