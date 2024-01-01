---
title: "Outlook Macro Execution Without Warning Setting Enabled"
status: "test"
created: "2021/04/05"
last_modified: "2023/08/17"
tags: [persistence, command_and_control, t1137, t1008, t1546, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Outlook Macro Execution Without Warning Setting Enabled

### Description

Detects the modification of Outlook security setting to allow unprompted execution of macros.

```yml
title: Outlook Macro Execution Without Warning Setting Enabled
id: e3b50fa5-3c3f-444e-937b-0a99d33731cd
status: test
description: Detects the modification of Outlook security setting to allow unprompted execution of macros.
references:
    - https://www.mdsec.co.uk/2020/11/a-fresh-outlook-on-mail-based-persistence/
    - https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=53
author: '@ScoubiMtl'
date: 2021/04/05
modified: 2023/08/17
tags:
    - attack.persistence
    - attack.command_and_control
    - attack.t1137
    - attack.t1008
    - attack.t1546
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\Outlook\Security\Level'
        Details|contains: '0x00000001' # Enable all Macros
    condition: selection
falsepositives:
    - Unlikely
level: high

```
