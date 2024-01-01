---
title: "Suspicious Add User to Remote Desktop Users Group"
status: "test"
created: "2021/12/06"
last_modified: "2022/09/09"
tags: [persistence, lateral_movement, t1133, t1136_001, t1021_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious Add User to Remote Desktop Users Group

### Description

Detects suspicious command line in which a user gets added to the local Remote Desktop Users group

```yml
title: Suspicious Add User to Remote Desktop Users Group
id: ffa28e60-bdb1-46e0-9f82-05f7a61cc06e
related:
    - id: ad720b90-25ad-43ff-9b5e-5c841facc8e5 # Admin groups
      type: similar
status: test
description: Detects suspicious command line in which a user gets added to the local Remote Desktop Users group
references:
    - https://www.microsoft.com/security/blog/2021/11/16/evolving-trends-in-iranian-threat-actor-activity-mstic-presentation-at-cyberwarcon-2021/
author: Florian Roth (Nextron Systems)
date: 2021/12/06
modified: 2022/09/09
tags:
    - attack.persistence
    - attack.lateral_movement
    - attack.t1133
    - attack.t1136.001
    - attack.t1021.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_main:
        - CommandLine|contains|all:
              - 'localgroup '
              - ' /add'
        - CommandLine|contains|all:
              - 'Add-LocalGroupMember '
              - ' -Group '
    selection_group:
        CommandLine|contains:
            - 'Remote Desktop Users'
            - 'Utilisateurs du Bureau à distance' # French for "Remote Desktop Users"
            - 'Usuarios de escritorio remoto' # Spanish for "Remote Desktop Users"
    condition: all of selection_*
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Administrative activity
level: high

```