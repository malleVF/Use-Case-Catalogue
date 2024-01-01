---
title: "UAC Bypass Abusing Winsat Path Parsing - Process"
status: "test"
created: "2021/08/30"
last_modified: "2022/10/09"
tags: [defense_evasion, privilege_escalation, t1548_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## UAC Bypass Abusing Winsat Path Parsing - Process

### Description

Detects the pattern of UAC Bypass using a path parsing issue in winsat.exe (UACMe 52)

```yml
title: UAC Bypass Abusing Winsat Path Parsing - Process
id: 7a01183d-71a2-46ad-ad5c-acd989ac1793
status: test
description: Detects the pattern of UAC Bypass using a path parsing issue in winsat.exe (UACMe 52)
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
        ParentImage|endswith: '\AppData\Local\Temp\system32\winsat.exe'
        ParentCommandLine|contains: 'C:\Windows \system32\winsat.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```
