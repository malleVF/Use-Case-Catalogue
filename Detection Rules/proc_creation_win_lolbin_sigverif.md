---
title: "Suspicious Sigverif Execution"
status: "test"
created: "2022/08/19"
last_modified: ""
tags: [defense_evasion, t1216, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Suspicious Sigverif Execution

### Description

Detects the execution of sigverif binary as a parent process which could indicate it being used as a LOLBIN to proxy execution

```yml
title: Suspicious Sigverif Execution
id: 7d4aaec2-08ed-4430-8b96-28420e030e04
status: test
description: Detects the execution of sigverif binary as a parent process which could indicate it being used as a LOLBIN to proxy execution
references:
    - https://www.hexacorn.com/blog/2018/04/27/i-shot-the-sigverif-exe-the-gui-based-lolbin/
    - https://twitter.com/0gtweet/status/1457676633809330184
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
        ParentImage|endswith: '\sigverif.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
