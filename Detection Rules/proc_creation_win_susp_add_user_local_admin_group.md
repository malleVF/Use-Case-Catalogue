---
title: "Add User to Local Administrators Group"
status: "experimental"
created: "2022/08/12"
last_modified: "2023/03/02"
tags: [persistence, t1098, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Add User to Local Administrators Group

### Description

Detects suspicious command line that adds an account to the local administrators/administrateurs group

```yml
title: Add User to Local Administrators Group
id: ad720b90-25ad-43ff-9b5e-5c841facc8e5
related:
    - id: ffa28e60-bdb1-46e0-9f82-05f7a61cc06e # Remote Desktop groups
      type: similar
status: experimental
description: Detects suspicious command line that adds an account to the local administrators/administrateurs group
references:
    - https://blog.talosintelligence.com/2022/08/recent-cyber-attack.html?m=1
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2022/08/12
modified: 2023/03/02
tags:
    - attack.persistence
    - attack.t1098
logsource:
    category: process_creation
    product: windows
detection:
    selection_main:
        - CommandLine|contains|all:
              # net.exe
              - 'localgroup '
              - ' /add'
        - CommandLine|contains|all:
              # powershell.exe
              - 'Add-LocalGroupMember '
              - ' -Group '
    selection_group:
        CommandLine|contains:
            - ' administrators '
            - ' administrateur' # Typo without an 'S' so we catch both
    condition: all of selection_*
falsepositives:
    - Administrative activity
level: medium

```
