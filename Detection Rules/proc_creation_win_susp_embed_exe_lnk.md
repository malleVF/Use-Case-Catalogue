---
title: "Hidden Powershell in Link File Pattern"
status: "test"
created: "2022/02/06"
last_modified: ""
tags: [execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Hidden Powershell in Link File Pattern

### Description

Detects events that appear when a user click on a link file with a powershell command in it

```yml
title: Hidden Powershell in Link File Pattern
id: 30e92f50-bb5a-4884-98b5-d20aa80f3d7a
status: test
description: Detects events that appear when a user click on a link file with a powershell command in it
references:
    - https://www.x86matthew.com/view_post?id=embed_exe_lnk
author: frack113
date: 2022/02/06
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: C:\Windows\explorer.exe
        Image: C:\Windows\System32\cmd.exe
        CommandLine|contains|all:
            - 'powershell'
            - '.lnk'
    condition: selection
falsepositives:
    - Legitimate commands in .lnk files
level: medium

```
