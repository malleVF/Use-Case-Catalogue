---
title: "Potential RDP Session Hijacking Activity"
status: "test"
created: "2022/12/27"
last_modified: ""
tags: [execution, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Potential RDP Session Hijacking Activity

### Description

Detects potential RDP Session Hijacking activity on Windows systems

```yml
title: Potential RDP Session Hijacking Activity
id: 224f140f-3553-4cd1-af78-13d81bf9f7cc
status: test
description: Detects potential RDP Session Hijacking activity on Windows systems
references:
    - https://twitter.com/Moti_B/status/909449115477659651
author: '@juju4'
date: 2022/12/27
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\tscon.exe'
        - OriginalFileName: 'tscon.exe'
    selection_integrity:
        IntegrityLevel: SYSTEM
    condition: all of selection_*
falsepositives:
    - Administrative activity
level: medium

```
