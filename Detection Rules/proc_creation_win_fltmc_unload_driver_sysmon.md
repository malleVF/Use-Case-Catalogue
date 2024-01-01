---
title: "Sysmon Driver Unloaded Via Fltmc.EXE"
status: "test"
created: "2019/10/23"
last_modified: "2023/02/13"
tags: [defense_evasion, t1070, t1562, t1562_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Sysmon Driver Unloaded Via Fltmc.EXE

### Description

Detects possible Sysmon filter driver unloaded via fltmc.exe

```yml
title: Sysmon Driver Unloaded Via Fltmc.EXE
id: 4d7cda18-1b12-4e52-b45c-d28653210df8
related:
    - id: 4931188c-178e-4ee7-a348-39e8a7a56821 # Generic
      type: similar
status: test
description: Detects possible Sysmon filter driver unloaded via fltmc.exe
references:
    - https://www.darkoperator.com/blog/2018/10/5/operating-offensively-against-sysmon
author: Kirill Kiryanov, oscd.community
date: 2019/10/23
modified: 2023/02/13
tags:
    - attack.defense_evasion
    - attack.t1070
    - attack.t1562
    - attack.t1562.002
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        - Image|endswith: '\fltMC.exe'
        - OriginalFileName: 'fltMC.exe'
    selection_cli:
        CommandLine|contains|all:
            - 'unload'
            - 'sysmon'
    condition: all of selection_*
falsepositives:
    - Unlikely
level: high

```