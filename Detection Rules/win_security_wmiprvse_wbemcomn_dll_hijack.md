---
title: "T1047 Wmiprvse Wbemcomn DLL Hijack"
status: "test"
created: "2020/10/12"
last_modified: "2022/02/24"
tags: [execution, t1047, lateral_movement, t1021_002, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## T1047 Wmiprvse Wbemcomn DLL Hijack

### Description

Detects a threat actor creating a file named `wbemcomn.dll` in the `C:\Windows\System32\wbem\` directory over the network for a WMI DLL Hijack scenario.

```yml
title: T1047 Wmiprvse Wbemcomn DLL Hijack
id: f6c68d5f-e101-4b86-8c84-7d96851fd65c
status: test
description: Detects a threat actor creating a file named `wbemcomn.dll` in the `C:\Windows\System32\wbem\` directory over the network for a WMI DLL Hijack scenario.
references:
    - https://threathunterplaybook.com/hunts/windows/201009-RemoteWMIWbemcomnDLLHijack/notebook.html
author: Roberto Rodriguez @Cyb3rWard0g, Open Threat Research (OTR)
date: 2020/10/12
modified: 2022/02/24
tags:
    - attack.execution
    - attack.t1047
    - attack.lateral_movement
    - attack.t1021.002
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5145
        RelativeTargetName|endswith: '\wbem\wbemcomn.dll'
    filter:
        SubjectUserName|endswith: '$'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high

```