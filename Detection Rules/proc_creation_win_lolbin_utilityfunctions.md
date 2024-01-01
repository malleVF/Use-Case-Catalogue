---
title: "UtilityFunctions.ps1 Proxy Dll"
status: "test"
created: "2022/05/28"
last_modified: ""
tags: [defense_evasion, t1216, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## UtilityFunctions.ps1 Proxy Dll

### Description

Detects the use of a Microsoft signed script executing a managed DLL with PowerShell.

```yml
title: UtilityFunctions.ps1 Proxy Dll
id: 0403d67d-6227-4ea8-8145-4e72db7da120
status: test
description: Detects the use of a Microsoft signed script executing a managed DLL with PowerShell.
references:
    - https://lolbas-project.github.io/lolbas/Scripts/UtilityFunctions/
author: frack113
date: 2022/05/28
tags:
    - attack.defense_evasion
    - attack.t1216
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'UtilityFunctions.ps1'
            - 'RegSnapin '
    condition: selection
falsepositives:
    - Unknown
level: medium

```
