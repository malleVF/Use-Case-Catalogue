---
title: "Psexec Execution"
status: "test"
created: "2020/10/30"
last_modified: "2023/02/28"
tags: [execution, t1569, t1021, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Psexec Execution

### Description

Detects user accept agreement execution in psexec commandline

```yml
title: Psexec Execution
id: 730fc21b-eaff-474b-ad23-90fd265d4988
status: test
description: Detects user accept agreement execution in psexec commandline
references:
    - https://www.fireeye.com/blog/threat-research/2020/10/kegtap-and-singlemalt-with-a-ransomware-chaser.html
author: omkar72
date: 2020/10/30
modified: 2023/02/28
tags:
    - attack.execution
    - attack.t1569
    - attack.t1021
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\psexec.exe'
        - OriginalFileName: 'psexec.c'
    condition: selection
falsepositives:
    - Administrative scripts.
level: medium

```