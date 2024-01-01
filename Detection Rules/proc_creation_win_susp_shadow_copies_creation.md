---
title: "Shadow Copies Creation Using Operating Systems Utilities"
status: "test"
created: "2019/10/22"
last_modified: "2022/11/10"
tags: [credential_access, t1003, t1003_002, t1003_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Shadow Copies Creation Using Operating Systems Utilities

### Description

Shadow Copies creation using operating systems utilities, possible credential access

```yml
title: Shadow Copies Creation Using Operating Systems Utilities
id: b17ea6f7-6e90-447e-a799-e6c0a493d6ce
status: test
description: Shadow Copies creation using operating systems utilities, possible credential access
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
    - https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/tutorial-for-ntds-goodness-vssadmin-wmis-ntdsdit-system/
author: Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community
date: 2019/10/22
modified: 2022/11/10
tags:
    - attack.credential_access
    - attack.t1003
    - attack.t1003.002
    - attack.t1003.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\powershell.exe'
              - '\pwsh.exe'
              - '\wmic.exe'
              - '\vssadmin.exe'
        - OriginalFileName:
              - 'PowerShell.EXE'
              - 'pwsh.dll'
              - 'wmic.exe'
              - 'VSSADMIN.EXE'
    selection_cli:
        CommandLine|contains|all:
            - 'shadow'
            - 'create'
    condition: all of selection_*
falsepositives:
    - Legitimate administrator working with shadow copies, access for backup purposes
level: medium

```
