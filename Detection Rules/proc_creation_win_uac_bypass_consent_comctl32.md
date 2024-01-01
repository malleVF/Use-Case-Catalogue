---
title: "UAC Bypass Using Consent and Comctl32 - Process"
status: "test"
created: "2021/08/23"
last_modified: "2022/10/09"
tags: [defense_evasion, privilege_escalation, t1548_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## UAC Bypass Using Consent and Comctl32 - Process

### Description

Detects the pattern of UAC Bypass using consent.exe and comctl32.dll (UACMe 22)

```yml
title: UAC Bypass Using Consent and Comctl32 - Process
id: 1ca6bd18-0ba0-44ca-851c-92ed89a61085
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
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\consent.exe'
        Image|endswith: '\werfault.exe'
        IntegrityLevel:
            - 'High'
            - 'System'
    condition: selection
falsepositives:
    - Unknown
level: high

```
