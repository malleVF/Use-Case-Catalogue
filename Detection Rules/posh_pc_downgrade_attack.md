---
title: "PowerShell Downgrade Attack - PowerShell"
status: "test"
created: "2017/03/22"
last_modified: "2023/10/27"
tags: [defense_evasion, execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## PowerShell Downgrade Attack - PowerShell

### Description

Detects PowerShell downgrade attack by comparing the host versions with the actually used engine version 2.0

```yml
title: PowerShell Downgrade Attack - PowerShell
id: 6331d09b-4785-4c13-980f-f96661356249
status: test
description: Detects PowerShell downgrade attack by comparing the host versions with the actually used engine version 2.0
references:
    - http://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks/
author: Florian Roth (Nextron Systems), Lee Holmes (idea), Harish Segar (improvements)
date: 2017/03/22
modified: 2023/10/27
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: ps_classic_start
detection:
    selection:
        Data|contains: 'EngineVersion=2.'
    filter_main:
        Data|contains: 'HostVersion=2.'
    condition: selection and not filter_main
falsepositives:
    - Unknown
level: medium

```
