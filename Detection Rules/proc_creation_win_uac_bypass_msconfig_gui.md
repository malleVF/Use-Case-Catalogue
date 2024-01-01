---
title: "UAC Bypass Using MSConfig Token Modification - Process"
status: "test"
created: "2021/08/30"
last_modified: "2022/10/09"
tags: [defense_evasion, privilege_escalation, t1548_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## UAC Bypass Using MSConfig Token Modification - Process

### Description

Detects the pattern of UAC Bypass using a msconfig GUI hack (UACMe 55)

```yml
title: UAC Bypass Using MSConfig Token Modification - Process
id: ad92e3f9-7eb6-460e-96b1-582b0ccbb980
status: test
description: Detects the pattern of UAC Bypass using a msconfig GUI hack (UACMe 55)
references:
    - https://github.com/hfiref0x/UACME
author: Christian Burkard (Nextron Systems)
date: 2021/08/30
modified: 2022/10/09
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1548.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        IntegrityLevel:
            - 'High'
            - 'System'
        ParentImage|endswith: '\AppData\Local\Temp\pkgmgr.exe'
        CommandLine: '"C:\Windows\system32\msconfig.exe" -5'
    condition: selection
falsepositives:
    - Unknown
level: high

```
