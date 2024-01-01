---
title: "Suspicious Extexport Execution"
status: "test"
created: "2021/11/26"
last_modified: "2022/05/16"
tags: [defense_evasion, t1218, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Suspicious Extexport Execution

### Description

Extexport.exe loads dll and is execute from other folder the original path

```yml
title: Suspicious Extexport Execution
id: fb0b815b-f5f6-4f50-970f-ffe21f253f7a
status: test
description: Extexport.exe loads dll and is execute from other folder the original path
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Extexport/
author: frack113
date: 2021/11/26
modified: 2022/05/16
tags:
    - attack.defense_evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - CommandLine|contains: Extexport.exe
        - Image|endswith: '\Extexport.exe'
        - OriginalFileName: 'extexport.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
