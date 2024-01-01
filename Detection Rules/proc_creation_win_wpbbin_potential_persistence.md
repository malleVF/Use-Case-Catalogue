---
title: "UEFI Persistence Via Wpbbin - ProcessCreation"
status: "test"
created: "2022/07/18"
last_modified: ""
tags: [persistence, defense_evasion, t1542_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## UEFI Persistence Via Wpbbin - ProcessCreation

### Description

Detects execution of the binary "wpbbin" which is used as part of the UEFI based persistence method described in the reference section

```yml
title: UEFI Persistence Via Wpbbin - ProcessCreation
id: 4abc0ec4-db5a-412f-9632-26659cddf145
status: test
description: Detects execution of the binary "wpbbin" which is used as part of the UEFI based persistence method described in the reference section
references:
    - https://grzegorztworek.medium.com/using-uefi-to-inject-executable-files-into-bitlocker-protected-drives-8ff4ca59c94c
    - https://persistence-info.github.io/Data/wpbbin.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/07/18
tags:
    - attack.persistence
    - attack.defense_evasion
    - attack.t1542.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image: 'C:\Windows\System32\wpbbin.exe'
    condition: selection
falsepositives:
    - Legitimate usage of the file by hardware manufacturer such as lenovo (Thanks @0gtweet for the tip)
level: high

```