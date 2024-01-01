---
title: "Remote LSASS Process Access Through Windows Remote Management"
status: "stable"
created: "2019/05/20"
last_modified: "2023/11/29"
tags: [credential_access, execution, t1003_001, t1059_001, lateral_movement, t1021_006, s0002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Remote LSASS Process Access Through Windows Remote Management

### Description

Detects remote access to the LSASS process via WinRM. This could be a sign of credential dumping from tools like mimikatz.

```yml
title: Remote LSASS Process Access Through Windows Remote Management
id: aa35a627-33fb-4d04-a165-d33b4afca3e8
status: stable
description: Detects remote access to the LSASS process via WinRM. This could be a sign of credential dumping from tools like mimikatz.
references:
    - https://pentestlab.blog/2018/05/15/lateral-movement-winrm/
author: Patryk Prauze - ING Tech
date: 2019/05/20
modified: 2023/11/29
tags:
    - attack.credential_access
    - attack.execution
    - attack.t1003.001
    - attack.t1059.001
    - attack.lateral_movement
    - attack.t1021.006
    - attack.s0002
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        SourceImage|endswith: ':\Windows\system32\wsmprovhost.exe'
    filter_main_access:
        GrantedAccess: '0x80000000'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unlikely
level: high

```
