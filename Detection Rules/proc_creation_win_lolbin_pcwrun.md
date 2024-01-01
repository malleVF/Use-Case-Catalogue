---
title: "Indirect Command Execution By Program Compatibility Wizard"
status: "test"
created: "2020/10/12"
last_modified: "2021/11/27"
tags: [defense_evasion, t1218, execution, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "low"
---

## Indirect Command Execution By Program Compatibility Wizard

### Description

Detect indirect command execution via Program Compatibility Assistant pcwrun.exe

```yml
title: Indirect Command Execution By Program Compatibility Wizard
id: b97cd4b1-30b8-4a9d-bd72-6293928d52bc
status: test
description: Detect indirect command execution via Program Compatibility Assistant pcwrun.exe
references:
    - https://twitter.com/pabraeken/status/991335019833708544
    - https://lolbas-project.github.io/lolbas/Binaries/Pcwrun/
author: A. Sungurov , oscd.community
date: 2020/10/12
modified: 2021/11/27
tags:
    - attack.defense_evasion
    - attack.t1218
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\pcwrun.exe'
    condition: selection
fields:
    - ComputerName
    - User
    - ParentCommandLine
    - CommandLine
falsepositives:
    - Need to use extra processing with 'unique_count' / 'filter' to focus on outliers as opposed to commonly seen artifacts
    - Legit usage of scripts
level: low

```