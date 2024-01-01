---
title: "Enable Microsoft Dynamic Data Exchange"
status: "test"
created: "2022/02/26"
last_modified: "2023/08/17"
tags: [execution, t1559_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Enable Microsoft Dynamic Data Exchange

### Description

Enable Dynamic Data Exchange protocol (DDE) in all supported editions of Microsoft Word or Excel.

```yml
title: Enable Microsoft Dynamic Data Exchange
id: 63647769-326d-4dde-a419-b925cc0caf42
status: test
description: Enable Dynamic Data Exchange protocol (DDE) in all supported editions of Microsoft Word or Excel.
references:
    - https://msrc.microsoft.com/update-guide/vulnerability/ADV170021
author: frack113
date: 2022/02/26
modified: 2023/08/17
tags:
    - attack.execution
    - attack.t1559.002
logsource:
    category: registry_set
    product: windows
detection:
    selection_word:
        TargetObject|endswith: '\Word\Security\AllowDDE'
        Details:
            - 'DWORD (0x00000001)'
            - 'DWORD (0x00000002)'
    selection_excel:
        TargetObject|endswith:
            - '\Excel\Security\DisableDDEServerLaunch'
            - '\Excel\Security\DisableDDEServerLookup'
        Details: 'DWORD (0x00000000)'
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: medium

```
