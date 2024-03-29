---
title: "Execution in Outlook Temp Folder"
status: "test"
created: "2019/10/01"
last_modified: "2022/10/09"
tags: [initial_access, t1566_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Execution in Outlook Temp Folder

### Description

Detects a suspicious program execution in Outlook temp folder

```yml
title: Execution in Outlook Temp Folder
id: a018fdc3-46a3-44e5-9afb-2cd4af1d4b39
status: test
description: Detects a suspicious program execution in Outlook temp folder
author: Florian Roth (Nextron Systems)
date: 2019/10/01
modified: 2022/10/09
tags:
    - attack.initial_access
    - attack.t1566.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|contains: '\Temporary Internet Files\Content.Outlook\'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high

```
