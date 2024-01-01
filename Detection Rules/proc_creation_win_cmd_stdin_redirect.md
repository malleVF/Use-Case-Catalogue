---
title: "Read Contents From Stdin Via Cmd.EXE"
status: "experimental"
created: "2023/03/07"
last_modified: ""
tags: [execution, t1059_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Read Contents From Stdin Via Cmd.EXE

### Description

Detect the use of "<" to read and potentially execute a file via cmd.exe

```yml
title: Read Contents From Stdin Via Cmd.EXE
id: 241e802a-b65e-484f-88cd-c2dc10f9206d
related:
    - id: 00a4bacd-6db4-46d5-9258-a7d5ebff4003
      type: obsoletes
status: experimental
description: Detect the use of "<" to read and potentially execute a file via cmd.exe
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1059.003/T1059.003.md
    - https://web.archive.org/web/20220306121156/https://www.x86matthew.com/view_post?id=ntdll_pipe
author: frack113, Nasreddine Bencherchali (Nextron Systems)
date: 2023/03/07
tags:
    - attack.execution
    - attack.t1059.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmd:
        - OriginalFileName: 'Cmd.Exe'
        - Image|endswith: '\cmd.exe'
    selection_cli:
        CommandLine|contains: '<'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium

```