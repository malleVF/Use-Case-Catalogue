---
title: "Potential DLL Sideloading Of DBGCORE.DLL"
status: "experimental"
created: "2022/10/25"
last_modified: "2023/05/05"
tags: [defense_evasion, persistence, privilege_escalation, t1574_001, t1574_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Potential DLL Sideloading Of DBGCORE.DLL

### Description

Detects DLL sideloading of "dbgcore.dll"

```yml
title: Potential DLL Sideloading Of DBGCORE.DLL
id: 9ca2bf31-0570-44d8-a543-534c47c33ed7
status: experimental
description: Detects DLL sideloading of "dbgcore.dll"
references:
    - https://hijacklibs.net/ # For list of DLLs that could be sideloaded (search for dlls mentioned here in there)
author: Nasreddine Bencherchali (Nextron Systems), Wietze Beukema (project and research)
date: 2022/10/25
modified: 2023/05/05
tags:
    - attack.defense_evasion
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1574.001
    - attack.t1574.002
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\dbgcore.dll'
    filter_main_generic:
        ImageLoaded|startswith:
            - 'C:\Program Files (x86)\'
            - 'C:\Program Files\'
            - 'C:\Windows\SoftwareDistribution\'
            - 'C:\Windows\System32\'
            - 'C:\Windows\SystemTemp\'
            - 'C:\Windows\SysWOW64\'
            - 'C:\Windows\WinSxS\'
    filter_optional_steam:
        ImageLoaded|endswith: '\Steam\bin\cef\cef.win7x64\dbgcore.dll'
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Legitimate applications loading their own versions of the DLL mentioned in this rule
level: medium

```