---
title: "Copy From Or To Admin Share Or Sysvol Folder"
status: "test"
created: "2019/12/30"
last_modified: "2023/11/15"
tags: [lateral_movement, collection, exfiltration, t1039, t1048, t1021_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Copy From Or To Admin Share Or Sysvol Folder

### Description

Detects a copy command or a copy utility execution to or from an Admin share or remote

```yml
title: Copy From Or To Admin Share Or Sysvol Folder
id: 855bc8b5-2ae8-402e-a9ed-b889e6df1900
status: test
description: Detects a copy command or a copy utility execution to or from an Admin share or remote
references:
    - https://twitter.com/SBousseaden/status/1211636381086339073
    - https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view
    - https://www.elastic.co/guide/en/security/current/remote-file-copy-to-a-hidden-share.html
    - https://www.microsoft.com/en-us/security/blog/2022/10/18/defenders-beware-a-case-for-post-ransomware-investigations/
author: Florian Roth (Nextron Systems), oscd.community, Teymur Kheirkhabarov @HeirhabarovT, Zach Stanford @svch0st, Nasreddine Bencherchali
date: 2019/12/30
modified: 2023/11/15
tags:
    - attack.lateral_movement
    - attack.collection
    - attack.exfiltration
    - attack.t1039
    - attack.t1048
    - attack.t1021.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_target:
        CommandLine|contains:
            - '\\\\*$'
            - '\Sysvol\'
    selection_other_tools:
        - Image|endswith:
              - '\robocopy.exe'
              - '\xcopy.exe'
        - OriginalFileName:
              - 'robocopy.exe'
              - 'XCOPY.EXE'
    selection_cmd_img:
        - Image|endswith: '\cmd.exe'
        - OriginalFileName: 'Cmd.Exe'
    selection_cmd_cli:
        CommandLine|contains: 'copy'
    selection_pwsh_img:
        - Image|contains:
              - '\powershell.exe'
              - '\pwsh.exe'
        - OriginalFileName:
              - 'PowerShell.EXE'
              - 'pwsh.dll'
    selection_pwsh_cli:
        CommandLine|contains:
            - 'copy-item'
            - 'copy '
            - 'cpi '
            - ' cp '
            - 'move '
            - 'move-item'
            - ' mi '
            - ' mv '
    condition: selection_target and (selection_other_tools or all of selection_cmd_* or all of selection_pwsh_*)
falsepositives:
    - Administrative scripts
level: medium

```