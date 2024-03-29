---
title: "Suspicious File Created In PerfLogs"
status: "experimental"
created: "2023/05/05"
last_modified: ""
tags: [execution, t1059, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Suspicious File Created In PerfLogs

### Description

Detects suspicious file based on their extension being created in "C:\PerfLogs\". Note that this directory mostly contains ".etl" files

```yml
title: Suspicious File Created In PerfLogs
id: bbb7e38c-0b41-4a11-b306-d2a457b7ac2b
status: experimental
description: Detects suspicious file based on their extension being created in "C:\PerfLogs\". Note that this directory mostly contains ".etl" files
references:
    - Internal Research
    - https://labs.withsecure.com/publications/fin7-target-veeam-servers
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/05/05
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|startswith: 'C:\PerfLogs\'
        TargetFilename|endswith:
            - '.7z'
            - '.bat'
            - '.bin'
            - '.chm'
            - '.dll'
            - '.exe'
            - '.hta'
            - '.lnk'
            - '.ps1'
            - '.psm1'
            - '.py'
            - '.scr'
            - '.sys'
            - '.vbe'
            - '.vbs'
            - '.zip'
    condition: selection
falsepositives:
    - Unlikely
level: medium

```
