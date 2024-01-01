---
title: "New User Created Via Net.EXE"
status: "test"
created: "2018/10/30"
last_modified: "2023/02/21"
tags: [persistence, t1136_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## New User Created Via Net.EXE

### Description

Identifies the creation of local users via the net.exe command.

```yml
title: New User Created Via Net.EXE
id: cd219ff3-fa99-45d4-8380-a7d15116c6dc
related:
    - id: b9f0e6f5-09b4-4358-bae4-08408705bd5c
      type: similar
status: test
description: Identifies the creation of local users via the net.exe command.
references:
    - https://eqllib.readthedocs.io/en/latest/analytics/014c3f51-89c6-40f1-ac9c-5688f26090ab.html
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1136.001/T1136.001.md
author: Endgame, JHasenbusch (adapted to Sigma for oscd.community)
date: 2018/10/30
modified: 2023/02/21
tags:
    - attack.persistence
    - attack.t1136.001
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
            - 'user'
            - 'add'
    condition: all of selection_*
fields:
    - ComputerName
    - User
    - CommandLine
falsepositives:
    - Legitimate user creation.
    - Better use event IDs for user creation rather than command line rules.
level: medium

```