---
title: "HackTool - Covenant PowerShell Launcher"
status: "test"
created: "2020/06/04"
last_modified: "2023/02/21"
tags: [execution, defense_evasion, t1059_001, t1564_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## HackTool - Covenant PowerShell Launcher

### Description

Detects suspicious command lines used in Covenant luanchers

```yml
title: HackTool - Covenant PowerShell Launcher
id: c260b6db-48ba-4b4a-a76f-2f67644e99d2
status: test
description: Detects suspicious command lines used in Covenant luanchers
references:
    - https://posts.specterops.io/covenant-v0-5-eee0507b85ba
author: Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community
date: 2020/06/04
modified: 2023/02/21
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1059.001
    - attack.t1564.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        CommandLine|contains|all:
            - '-Sta'
            - '-Nop'
            - '-Window'
            - 'Hidden'
        CommandLine|contains:
            - '-Command'
            - '-EncodedCommand'
    selection_2:
        CommandLine|contains:
            - 'sv o (New-Object IO.MemorySteam);sv d '
            - 'mshta file.hta'
            - 'GruntHTTP'
            - '-EncodedCommand cwB2ACAAbwAgA'
    condition: 1 of selection_*
level: high

```
