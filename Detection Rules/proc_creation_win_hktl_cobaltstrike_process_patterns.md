---
title: "Potential CobaltStrike Process Patterns"
status: "experimental"
created: "2021/07/27"
last_modified: "2023/03/29"
tags: [execution, t1059, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Potential CobaltStrike Process Patterns

### Description

Detects potential process patterns related to Cobalt Strike beacon activity

```yml
title: Potential CobaltStrike Process Patterns
id: f35c5d71-b489-4e22-a115-f003df287317
status: experimental
description: Detects potential process patterns related to Cobalt Strike beacon activity
references:
    - https://hausec.com/2021/07/26/cobalt-strike-and-tradecraft/
    - https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2021/07/27
modified: 2023/03/29
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection_generic_1:
        CommandLine|endswith: 'cmd.exe /C whoami'
        ParentImage|startswith: 'C:\Temp\'
    selection_generic_2:
        ParentImage|endswith:
            - '\runonce.exe'
            - '\dllhost.exe'
        CommandLine|contains|all:
            - 'cmd.exe /c echo'
            - '> \\\\.\\pipe'
    selection_conhost_1:
        ParentCommandLine|contains|all:
            - 'cmd.exe /C echo'
            - ' > \\\\.\\pipe'
        CommandLine|endswith: 'conhost.exe 0xffffffff -ForceV1'
    selection_conhost_2:
        ParentCommandLine|endswith: '/C whoami'
        CommandLine|endswith: 'conhost.exe 0xffffffff -ForceV1'
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: high

```