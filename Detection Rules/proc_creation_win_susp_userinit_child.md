---
title: "Suspicious Userinit Child Process"
status: "test"
created: "2019/06/17"
last_modified: "2022/12/09"
tags: [defense_evasion, t1055, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Suspicious Userinit Child Process

### Description

Detects a suspicious child process of userinit

```yml
title: Suspicious Userinit Child Process
id: b655a06a-31c0-477a-95c2-3726b83d649d
status: test
description: Detects a suspicious child process of userinit
references:
    - https://twitter.com/SBousseaden/status/1139811587760562176
author: Florian Roth (Nextron Systems), Samir Bousseaden (idea)
date: 2019/06/17
modified: 2022/12/09
tags:
    - attack.defense_evasion
    - attack.t1055
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\userinit.exe'
    filter1:
        CommandLine|contains: '\netlogon\'
    filter2:
        - Image|endswith: '\explorer.exe'
        - OriginalFileName: 'explorer.exe'
    condition: selection and not 1 of filter*
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Administrative scripts
level: medium

```
