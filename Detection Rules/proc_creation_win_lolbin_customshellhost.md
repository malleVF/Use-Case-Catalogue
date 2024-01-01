---
title: "Suspicious CustomShellHost Execution"
status: "test"
created: "2022/08/19"
last_modified: ""
tags: [defense_evasion, t1216, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Suspicious CustomShellHost Execution

### Description

Detects the execution of CustomShellHost binary where the child isn't located in 'C:\Windows\explorer.exe'

```yml
title: Suspicious CustomShellHost Execution
id: 84b14121-9d14-416e-800b-f3b829c5a14d
status: test
description: Detects the execution of CustomShellHost binary where the child isn't located in 'C:\Windows\explorer.exe'
references:
    - https://github.com/LOLBAS-Project/LOLBAS/pull/180
    - https://lolbas-project.github.io/lolbas/Binaries/CustomShellHost/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/08/19
tags:
    - attack.defense_evasion
    - attack.t1216
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\CustomShellHost.exe'
    filter:
        Image: 'C:\Windows\explorer.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: medium

```
