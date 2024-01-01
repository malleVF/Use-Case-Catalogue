---
title: "HackTool - CACTUSTORCH Remote Thread Creation"
status: "test"
created: "2019/02/01"
last_modified: "2023/05/05"
tags: [defense_evasion, execution, t1055_012, t1059_005, t1059_007, t1218_005, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## HackTool - CACTUSTORCH Remote Thread Creation

### Description

Detects remote thread creation from CACTUSTORCH as described in references.

```yml
title: HackTool - CACTUSTORCH Remote Thread Creation
id: 2e4e488a-6164-4811-9ea1-f960c7359c40
status: test
description: Detects remote thread creation from CACTUSTORCH as described in references.
references:
    - https://twitter.com/SBousseaden/status/1090588499517079552 # Deleted
    - https://github.com/mdsecactivebreach/CACTUSTORCH
author: '@SBousseaden (detection), Thomas Patzke (rule)'
date: 2019/02/01
modified: 2023/05/05
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1055.012
    - attack.t1059.005
    - attack.t1059.007
    - attack.t1218.005
logsource:
    product: windows
    category: create_remote_thread
detection:
    selection:
        SourceImage|endswith:
            - '\System32\cscript.exe'
            - '\System32\wscript.exe'
            - '\System32\mshta.exe'
            - '\winword.exe'
            - '\excel.exe'
        TargetImage|contains: '\SysWOW64\'
        StartModule: null
    condition: selection
falsepositives:
    - Unknown
level: high

```
