---
title: "RemCom Service File Creation"
status: "test"
created: "2023/08/04"
last_modified: ""
tags: [execution, t1569_002, s0029, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## RemCom Service File Creation

### Description

Detects default RemCom service filename which indicates RemCom service installation and execution

```yml
title: RemCom Service File Creation
id: 7eff1a7f-dd45-4c20-877a-f21e342a7611
status: test
description: Detects default RemCom service filename which indicates RemCom service installation and execution
references:
    - https://github.com/kavika13/RemCom/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/08/04
tags:
    - attack.execution
    - attack.t1569.002
    - attack.s0029
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: '\RemComSvc.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
