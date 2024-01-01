---
title: "File Download Via Bitsadmin To An Uncommon Target Folder"
status: "experimental"
created: "2022/06/28"
last_modified: "2023/02/15"
tags: [defense_evasion, persistence, t1197, s0190, t1036_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## File Download Via Bitsadmin To An Uncommon Target Folder

### Description

Detects usage of bitsadmin downloading a file to uncommon target folder

```yml
title: File Download Via Bitsadmin To An Uncommon Target Folder
id: 6e30c82f-a9f8-4aab-b79c-7c12bce6f248
status: experimental
description: Detects usage of bitsadmin downloading a file to uncommon target folder
references:
    - https://blog.netspi.com/15-ways-to-download-a-file/#bitsadmin
    - https://isc.sans.edu/diary/22264
    - https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/
    - https://blog.talosintelligence.com/breaking-the-silence-recent-truebot-activity/
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2022/06/28
modified: 2023/02/15
tags:
    - attack.defense_evasion
    - attack.persistence
    - attack.t1197
    - attack.s0190
    - attack.t1036.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\bitsadmin.exe'
        - OriginalFileName: 'bitsadmin.exe'
    selection_flags:
        CommandLine|contains:
            - ' /transfer '
            - ' /create '
            - ' /addfile '
    selection_folder:
        CommandLine|contains:
            - '%AppData%'
            - '%temp%'
            - '%tmp%'
            - '\AppData\Local\'
            - 'C:\Windows\Temp\'
    condition: all of selection_*
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: medium

```
