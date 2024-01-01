---
title: "UAC Bypass Using DismHost"
status: "test"
created: "2021/08/30"
last_modified: "2022/10/09"
tags: [defense_evasion, privilege_escalation, t1548_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## UAC Bypass Using DismHost

### Description

Detects the pattern of UAC Bypass using DismHost DLL hijacking (UACMe 63)

```yml
title: UAC Bypass Using DismHost
id: 853e74f9-9392-4935-ad3b-2e8c040dae86
status: test
description: Detects the pattern of UAC Bypass using DismHost DLL hijacking (UACMe 63)
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
        ParentImage|contains|all:
            - 'C:\Users\'
            - '\AppData\Local\Temp\'
            - '\DismHost.exe'
        IntegrityLevel:
            - 'High'
            - 'System'
    condition: selection
falsepositives:
    - Unknown
level: high

```