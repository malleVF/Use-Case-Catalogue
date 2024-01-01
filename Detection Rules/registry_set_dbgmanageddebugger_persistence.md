---
title: "Potential Registry Persistence Attempt Via DbgManagedDebugger"
status: "experimental"
created: "2022/08/07"
last_modified: "2023/08/17"
tags: [persistence, t1574, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Potential Registry Persistence Attempt Via DbgManagedDebugger

### Description

Detects the addition of the "Debugger" value to the "DbgManagedDebugger" key in order to achieve persistence. Which will get invoked when an application crashes

```yml
title: Potential Registry Persistence Attempt Via DbgManagedDebugger
id: 9827ae57-3802-418f-994b-d5ecf5cd974b
status: experimental
description: Detects the addition of the "Debugger" value to the "DbgManagedDebugger" key in order to achieve persistence. Which will get invoked when an application crashes
references:
    - https://www.hexacorn.com/blog/2013/09/19/beyond-good-ol-run-key-part-4/
    - https://github.com/last-byte/PersistenceSniper
author: frack113
date: 2022/08/07
modified: 2023/08/17
tags:
    - attack.persistence
    - attack.t1574
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\Microsoft\.NETFramework\DbgManagedDebugger'
    filter:
        Details: '"C:\Windows\system32\vsjitdebugger.exe" PID %d APPDOM %d EXTEXT "%s" EVTHDL %d'
    condition: selection and not filter
falsepositives:
    - Legitimate use of the key to setup a debugger. Which is often the case on developers machines
level: medium

```