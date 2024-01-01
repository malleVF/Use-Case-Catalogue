---
title: "New BITS Job Created Via PowerShell"
status: "experimental"
created: "2022/03/01"
last_modified: "2023/03/27"
tags: [defense_evasion, persistence, t1197, detection_rule]
logsrc_product: "windows"
logsrc_service: "bits-client"
level: "low"
---

## New BITS Job Created Via PowerShell

### Description

Detects the creation of a new bits job by PowerShell

```yml
title: New BITS Job Created Via PowerShell
id: fe3a2d49-f255-4d10-935c-bda7391108eb
status: experimental
description: Detects the creation of a new bits job by PowerShell
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1197/T1197.md
author: frack113
date: 2022/03/01
modified: 2023/03/27
tags:
    - attack.defense_evasion
    - attack.persistence
    - attack.t1197
logsource:
    product: windows
    service: bits-client
detection:
    selection:
        EventID: 3
        processPath|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    condition: selection
falsepositives:
    - Administrator PowerShell scripts
level: low

```