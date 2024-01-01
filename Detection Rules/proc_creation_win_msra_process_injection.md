---
title: "Potential Process Injection Via Msra.EXE"
status: "test"
created: "2022/06/24"
last_modified: "2023/02/03"
tags: [defense_evasion, t1055, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Potential Process Injection Via Msra.EXE

### Description

Detects potential process injection via Microsoft Remote Asssistance (Msra.exe) by looking at suspicious child processes spawned from the aforementioned process. It has been a target used by many threat actors and used for discovery and persistence tactics

```yml
title: Potential Process Injection Via Msra.EXE
id: 744a188b-0415-4792-896f-11ddb0588dbc
status: test
description: Detects potential process injection via Microsoft Remote Asssistance (Msra.exe) by looking at suspicious child processes spawned from the aforementioned process. It has been a target used by many threat actors and used for discovery and persistence tactics
references:
    - https://www.microsoft.com/security/blog/2021/12/09/a-closer-look-at-qakbots-latest-building-blocks-and-how-to-knock-them-down/
    - https://www.fortinet.com/content/dam/fortinet/assets/analyst-reports/ar-qakbot.pdf
author: Alexander McDonald
date: 2022/06/24
modified: 2023/02/03
tags:
    - attack.defense_evasion
    - attack.t1055
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\msra.exe'
        ParentCommandLine|endswith: 'msra.exe'
        Image|endswith:
            - '\arp.exe'
            - '\cmd.exe'
            - '\net.exe'
            - '\netstat.exe'
            - '\nslookup.exe'
            - '\route.exe'
            - '\schtasks.exe'
            - '\whoami.exe'
    condition: selection
falsepositives:
    - Legitimate use of Msra.exe
level: high

```
