---
title: "Function Call From Undocumented COM Interface EditionUpgradeManager"
status: "test"
created: "2020/10/07"
last_modified: "2023/11/30"
tags: [defense_evasion, privilege_escalation, t1548_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Function Call From Undocumented COM Interface EditionUpgradeManager

### Description

Detects function calls from the EditionUpgradeManager COM interface. Which is an interface that is not used by standard executables.

```yml
title: Function Call From Undocumented COM Interface EditionUpgradeManager
id: fb3722e4-1a06-46b6-b772-253e2e7db933
status: test
description: Detects function calls from the EditionUpgradeManager COM interface. Which is an interface that is not used by standard executables.
references:
    - https://www.snip2code.com/Snippet/4397378/UAC-bypass-using-EditionUpgradeManager-C/
    - https://gist.github.com/hfiref0x/de9c83966623236f5ebf8d9ae2407611
author: oscd.community, Dmitry Uchakin
date: 2020/10/07
modified: 2023/11/30
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1548.002
logsource:
    category: process_access
    product: windows
detection:
    selection:
        CallTrace|contains: 'editionupgrademanagerobj.dll'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
