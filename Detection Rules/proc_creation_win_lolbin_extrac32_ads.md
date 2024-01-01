---
title: "Suspicious Extrac32 Alternate Data Stream Execution"
status: "test"
created: "2021/11/26"
last_modified: "2022/12/30"
tags: [defense_evasion, t1564_004, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Suspicious Extrac32 Alternate Data Stream Execution

### Description

Extract data from cab file and hide it in an alternate data stream

```yml
title: Suspicious Extrac32 Alternate Data Stream Execution
id: 4b13db67-0c45-40f1-aba8-66a1a7198a1e
status: test
description: Extract data from cab file and hide it in an alternate data stream
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Extrac32/
author: frack113
date: 2021/11/26
modified: 2022/12/30
tags:
    - attack.defense_evasion
    - attack.t1564.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - extrac32.exe
            - .cab
        CommandLine|re: ':[^\\]'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
