---
title: "Recon Information for Export with Command Prompt"
status: "test"
created: "2021/07/30"
last_modified: "2022/09/13"
tags: [collection, t1119, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Recon Information for Export with Command Prompt

### Description

Once established within a system or network, an adversary may use automated techniques for collecting internal data.

```yml
title: Recon Information for Export with Command Prompt
id: aa2efee7-34dd-446e-8a37-40790a66efd7
related:
    - id: 8e0bb260-d4b2-4fff-bb8d-3f82118e6892
      type: similar
status: test
description: Once established within a system or network, an adversary may use automated techniques for collecting internal data.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1119/T1119.md
author: frack113
date: 2021/07/30
modified: 2022/09/13
tags:
    - attack.collection
    - attack.t1119
logsource:
    product: windows
    category: process_creation
detection:
    selection_image:
        - Image|endswith:
              - '\tree.com'
              - '\WMIC.exe'
              - '\doskey.exe'
              - '\sc.exe'
        - OriginalFileName:
              - 'wmic.exe'
              - 'DOSKEY.EXE'
              - 'sc.exe'
    selection_redirect:
        ParentCommandLine|contains:
            - ' > %TEMP%\'
            - ' > %TMP%\'
    condition: all of selection*
falsepositives:
    - Unknown
level: medium

```
