---
title: "New User Created Via Net.EXE With Never Expire Option"
status: "test"
created: "2022/07/12"
last_modified: "2023/02/21"
tags: [persistence, t1136_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## New User Created Via Net.EXE With Never Expire Option

### Description

Detects creation of local users via the net.exe command with the option "never expire"

```yml
title: New User Created Via Net.EXE With Never Expire Option
id: b9f0e6f5-09b4-4358-bae4-08408705bd5c
related:
    - id: cd219ff3-fa99-45d4-8380-a7d15116c6dc
      type: derived
status: test
description: Detects creation of local users via the net.exe command with the option "never expire"
references:
    - https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/07/12
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
            - 'expires:never'
    condition: all of selection_*
falsepositives:
    - Unlikely
level: high

```