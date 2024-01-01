---
title: "PUA - Crassus Execution"
status: "experimental"
created: "2023/04/17"
last_modified: ""
tags: [discovery, t1590_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## PUA - Crassus Execution

### Description

Detects Crassus, a Windows privilege escalation discovery tool, based on PE metadata characteristics.

```yml
title: PUA - Crassus Execution
id: 2c32b543-1058-4808-91c6-5b31b8bed6c5
status: experimental
description: Detects Crassus, a Windows privilege escalation discovery tool, based on PE metadata characteristics.
references:
    - https://github.com/vu-ls/Crassus
author: pH-T (Nextron Systems)
date: 2023/04/17
tags:
    - attack.discovery
    - attack.t1590.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\Crassus.exe'
        - OriginalFileName: 'Crassus.exe'
        - Description|contains: 'Crassus'
    condition: selection
falsepositives:
    - Unlikely
level: high

```
