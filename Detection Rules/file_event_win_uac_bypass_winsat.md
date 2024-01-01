---
title: "UAC Bypass Abusing Winsat Path Parsing - File"
status: "test"
created: "2021/08/30"
last_modified: "2022/10/09"
tags: [defense_evasion, privilege_escalation, t1548_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## UAC Bypass Abusing Winsat Path Parsing - File

### Description

Detects the pattern of UAC Bypass using a path parsing issue in winsat.exe (UACMe 52)

```yml
title: UAC Bypass Abusing Winsat Path Parsing - File
id: 155dbf56-e0a4-4dd0-8905-8a98705045e8
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
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|startswith: 'C:\Users\'
        TargetFilename|endswith:
            - '\AppData\Local\Temp\system32\winsat.exe'
            - '\AppData\Local\Temp\system32\winmm.dll'
    condition: selection
falsepositives:
    - Unknown
level: high

```