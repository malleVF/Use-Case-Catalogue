---
title: "Process Monitor Driver Creation By Non-Sysinternals Binary"
status: "experimental"
created: "2023/05/05"
last_modified: ""
tags: [persistence, privilege_escalation, t1068, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Process Monitor Driver Creation By Non-Sysinternals Binary

### Description

Detects creation of the Process Monitor driver by processes other than Process Monitor (procmon) itself.

```yml
title: Process Monitor Driver Creation By Non-Sysinternals Binary
id: a05baa88-e922-4001-bc4d-8738135f27de
status: experimental
description: Detects creation of the Process Monitor driver by processes other than Process Monitor (procmon) itself.
references:
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/05/05
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1068
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|contains: '\procmon'
        TargetFilename|endswith: '.sys'
    filter_main_process_explorer:
        Image|endswith:
            - '\procmon.exe'
            - '\procmon64.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Some false positives may occur with legitimate renamed process monitor binaries
level: medium

```