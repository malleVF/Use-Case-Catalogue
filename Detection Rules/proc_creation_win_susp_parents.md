---
title: "Suspicious Process Parents"
status: "test"
created: "2022/03/21"
last_modified: "2022/09/08"
tags: [defense_evasion, t1036, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious Process Parents

### Description

Detects suspicious parent processes that should not have any children or should only have a single possible child program

```yml
title: Suspicious Process Parents
id: cbec226f-63d9-4eca-9f52-dfb6652f24df
status: test
description: Detects suspicious parent processes that should not have any children or should only have a single possible child program
references:
    - https://twitter.com/x86matthew/status/1505476263464607744?s=12
    - https://svch0st.medium.com/stats-from-hunting-cobalt-strike-beacons-c17e56255f9b
author: Florian Roth (Nextron Systems)
date: 2022/03/21
modified: 2022/09/08
tags:
    - attack.defense_evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\minesweeper.exe'
            - '\winver.exe'
            - '\bitsadmin.exe'
    selection_special:
        ParentImage|endswith:
            - '\csrss.exe'
            - '\certutil.exe'
         # - '\schtasks.exe'
            - '\eventvwr.exe'
            - '\calc.exe'
            - '\notepad.exe'
    filter_special:
        Image|endswith:
            - '\WerFault.exe'
            - '\wermgr.exe'
            - '\conhost.exe' # csrss.exe, certutil.exe
            - '\mmc.exe'     # eventvwr.exe
            - '\win32calc.exe' # calc.exe
            - '\notepad.exe'
    filter_null:
        Image: null
    condition: selection or ( selection_special and not 1 of filter_* )
falsepositives:
    - Unknown
level: high

```