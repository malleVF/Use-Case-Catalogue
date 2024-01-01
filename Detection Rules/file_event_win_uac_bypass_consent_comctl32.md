---
title: "UAC Bypass Using Consent and Comctl32 - File"
status: "test"
created: "2021/08/23"
last_modified: "2022/10/09"
tags: [defense_evasion, privilege_escalation, t1548_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## UAC Bypass Using Consent and Comctl32 - File

### Description

Detects the pattern of UAC Bypass using consent.exe and comctl32.dll (UACMe 22)

```yml
title: UAC Bypass Using Consent and Comctl32 - File
id: 62ed5b55-f991-406a-85d9-e8e8fdf18789
status: test
description: Detects the pattern of UAC Bypass using consent.exe and comctl32.dll (UACMe 22)
references:
    - https://github.com/hfiref0x/UACME
author: Christian Burkard (Nextron Systems)
date: 2021/08/23
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
        TargetFilename|startswith: 'C:\Windows\System32\consent.exe.@'
        TargetFilename|endswith: '\comctl32.dll'
    condition: selection
falsepositives:
    - Unknown
level: high

```