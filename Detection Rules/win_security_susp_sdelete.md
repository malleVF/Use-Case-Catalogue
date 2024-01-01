---
title: "Secure Deletion with SDelete"
status: "test"
created: "2017/06/14"
last_modified: "2021/11/27"
tags: [impact, defense_evasion, t1070_004, t1027_005, t1485, t1553_002, s0195, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "medium"
---

## Secure Deletion with SDelete

### Description

Detects renaming of file while deletion with SDelete tool.

```yml
title: Secure Deletion with SDelete
id: 39a80702-d7ca-4a83-b776-525b1f86a36d
status: test
description: Detects renaming of file while deletion with SDelete tool.
references:
    - https://jpcertcc.github.io/ToolAnalysisResultSheet/details/sdelete.htm
    - https://www.jpcert.or.jp/english/pub/sr/ir_research.html
    - https://docs.microsoft.com/en-gb/sysinternals/downloads/sdelete
author: Thomas Patzke
date: 2017/06/14
modified: 2021/11/27
tags:
    - attack.impact
    - attack.defense_evasion
    - attack.t1070.004
    - attack.t1027.005
    - attack.t1485
    - attack.t1553.002
    - attack.s0195
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4656
            - 4663
            - 4658
        ObjectName|endswith:
            - '.AAA'
            - '.ZZZ'
    condition: selection
falsepositives:
    - Legitimate usage of SDelete
level: medium

```
