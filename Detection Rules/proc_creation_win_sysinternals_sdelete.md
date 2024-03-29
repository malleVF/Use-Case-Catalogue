---
title: "Potential File Overwrite Via Sysinternals SDelete"
status: "experimental"
created: "2021/06/03"
last_modified: "2023/02/28"
tags: [impact, t1485, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Potential File Overwrite Via Sysinternals SDelete

### Description

Detects the use of SDelete to erase a file not the free space

```yml
title: Potential File Overwrite Via Sysinternals SDelete
id: a4824fca-976f-4964-b334-0621379e84c4
status: experimental
description: Detects the use of SDelete to erase a file not the free space
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1485/T1485.md
author: frack113
date: 2021/06/03
modified: 2023/02/28
tags:
    - attack.impact
    - attack.t1485
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName: sdelete.exe
    filter:
        CommandLine|contains:
            - ' -h'
            - ' -c'
            - ' -z'
            - ' /\?'
    condition: selection and not filter
fields:
    - ComputerName
    - User
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high

```
