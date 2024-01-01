---
title: "UAC Bypass Using IEInstal - File"
status: "test"
created: "2021/08/30"
last_modified: "2022/10/09"
tags: [defense_evasion, privilege_escalation, t1548_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## UAC Bypass Using IEInstal - File

### Description

Detects the pattern of UAC Bypass using IEInstal.exe (UACMe 64)

```yml
title: UAC Bypass Using IEInstal - File
id: bdd8157d-8e85-4397-bb82-f06cc9c71dbb
status: test
description: Detects the pattern of UAC Bypass using IEInstal.exe (UACMe 64)
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
        Image: 'C:\Program Files\Internet Explorer\IEInstal.exe'
        TargetFilename|startswith: 'C:\Users\'
        TargetFilename|contains: '\AppData\Local\Temp\'
        TargetFilename|endswith: 'consent.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```
