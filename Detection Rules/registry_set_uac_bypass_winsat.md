---
title: "UAC Bypass Abusing Winsat Path Parsing - Registry"
status: "test"
created: "2021/08/30"
last_modified: "2023/08/17"
tags: [defense_evasion, privilege_escalation, t1548_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## UAC Bypass Abusing Winsat Path Parsing - Registry

### Description

Detects the pattern of UAC Bypass using a path parsing issue in winsat.exe (UACMe 52)

```yml
title: UAC Bypass Abusing Winsat Path Parsing - Registry
id: 6597be7b-ac61-4ac8-bef4-d3ec88174853
status: test
description: Detects the pattern of UAC Bypass using a path parsing issue in winsat.exe (UACMe 52)
references:
    - https://github.com/hfiref0x/UACME
author: Christian Burkard (Nextron Systems)
date: 2021/08/30
modified: 2023/08/17
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1548.002
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\Root\InventoryApplicationFile\winsat.exe|'
        TargetObject|endswith: '\LowerCaseLongPath'
        Details|startswith: 'c:\users\'
        Details|endswith: '\appdata\local\temp\system32\winsat.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```