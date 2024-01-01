---
title: "Automated Collection Command Prompt"
status: "test"
created: "2021/07/28"
last_modified: "2022/11/11"
tags: [collection, t1119, credential_access, t1552_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Automated Collection Command Prompt

### Description

Once established within a system or network, an adversary may use automated techniques for collecting internal data.

```yml
title: Automated Collection Command Prompt
id: f576a613-2392-4067-9d1a-9345fb58d8d1
status: test
description: Once established within a system or network, an adversary may use automated techniques for collecting internal data.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1119/T1119.md
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1552.001/T1552.001.md
author: frack113
date: 2021/07/28
modified: 2022/11/11
tags:
    - attack.collection
    - attack.t1119
    - attack.credential_access
    - attack.t1552.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_ext:
        CommandLine|contains:
            - '.doc'
            - '.docx'
            - '.xls'
            - '.xlsx'
            - '.ppt'
            - '.pptx'
            - '.rtf'
            - '.pdf'
            - '.txt'
    selection_other_dir:
        CommandLine|contains|all:
            - 'dir '
            - ' /b '
            - ' /s '
    selection_other_findstr:
        OriginalFileName: 'FINDSTR.EXE'
        CommandLine|contains:
            - ' /e '
            - ' /si '
    condition: selection_ext and 1 of selection_other_*
falsepositives:
    - Unknown
level: medium

```