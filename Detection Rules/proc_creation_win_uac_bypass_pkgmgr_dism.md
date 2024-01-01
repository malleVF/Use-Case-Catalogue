---
title: "UAC Bypass Using PkgMgr and DISM"
status: "test"
created: "2021/08/23"
last_modified: "2022/10/09"
tags: [defense_evasion, privilege_escalation, t1548_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## UAC Bypass Using PkgMgr and DISM

### Description

Detects the pattern of UAC Bypass using pkgmgr.exe and dism.exe (UACMe 23)

```yml
title: UAC Bypass Using PkgMgr and DISM
id: a743ceba-c771-4d75-97eb-8a90f7f4844c
status: test
description: Detects the pattern of UAC Bypass using pkgmgr.exe and dism.exe (UACMe 23)
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
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\pkgmgr.exe'
        Image|endswith: '\dism.exe'
        IntegrityLevel:
            - 'High'
            - 'System'
    condition: selection
falsepositives:
    - Unknown
level: high

```
