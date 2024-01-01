---
title: "Renamed SysInternals DebugView Execution"
status: "test"
created: "2020/05/28"
last_modified: "2023/02/14"
tags: [resource_development, t1588_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Renamed SysInternals DebugView Execution

### Description

Detects suspicious renamed SysInternals DebugView execution

```yml
title: Renamed SysInternals DebugView Execution
id: cd764533-2e07-40d6-a718-cfeec7f2da7f
status: test
description: Detects suspicious renamed SysInternals DebugView execution
references:
    - https://www.epicturla.com/blog/sysinturla
author: Florian Roth (Nextron Systems)
date: 2020/05/28
modified: 2023/02/14
tags:
    - attack.resource_development
    - attack.t1588.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Product: 'Sysinternals DebugView'
    filter:
        OriginalFileName: 'Dbgview.exe'
        Image|endswith: '\Dbgview.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high

```
