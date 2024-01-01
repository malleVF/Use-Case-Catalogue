---
title: "Amsi.DLL Loaded Via LOLBIN Process"
status: "experimental"
created: "2023/06/01"
last_modified: "2023/09/20"
tags: [defense_evasion, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Amsi.DLL Loaded Via LOLBIN Process

### Description

Detects loading of "Amsi.dll" by a living of the land process. This could be an indication of a "PowerShell without PowerShell" attack

```yml
title: Amsi.DLL Loaded Via LOLBIN Process
id: 6ec86d9e-912e-4726-91a2-209359b999b9
status: experimental
description: Detects loading of "Amsi.dll" by a living of the land process. This could be an indication of a "PowerShell without PowerShell" attack
references:
    - Internal Research
    - https://www.paloaltonetworks.com/blog/security-operations/stopping-powershell-without-powershell/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/06/01
modified: 2023/09/20
tags:
    - attack.defense_evasion
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\amsi.dll'
        Image|endswith:
            # TODO: Add more interesting processes
            - '\ExtExport.exe'
            - '\odbcconf.exe'
            - '\regsvr32.exe'
            - '\rundll32.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
