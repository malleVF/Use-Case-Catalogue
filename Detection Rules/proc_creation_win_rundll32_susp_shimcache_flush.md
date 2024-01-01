---
title: "ShimCache Flush"
status: "stable"
created: "2021/02/01"
last_modified: ""
tags: [defense_evasion, t1112, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## ShimCache Flush

### Description

Detects actions that clear the local ShimCache and remove forensic evidence

```yml
title: ShimCache Flush
id: b0524451-19af-4efa-a46f-562a977f792e
status: stable
description: Detects actions that clear the local ShimCache and remove forensic evidence
references:
    - https://medium.com/@blueteamops/shimcache-flush-89daff28d15e
author: Florian Roth (Nextron Systems)
date: 2021/02/01
tags:
    - attack.defense_evasion
    - attack.t1112
logsource:
    category: process_creation
    product: windows
detection:
    selection1a:
        CommandLine|contains|all:
            - 'rundll32'
            - 'apphelp.dll'
    selection1b:
        CommandLine|contains:
            - 'ShimFlushCache'
            - '#250'
    selection2a:
        CommandLine|contains|all:
            - 'rundll32'
            - 'kernel32.dll'
    selection2b:
        CommandLine|contains:
            - 'BaseFlushAppcompatCache'
            - '#46'
    condition: ( selection1a and selection1b ) or ( selection2a and selection2b )
fields:
    - Image
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high

```