---
title: "File Download Via Bitsadmin To A Suspicious Target Folder"
status: "experimental"
created: "2022/06/28"
last_modified: "2023/05/30"
tags: [defense_evasion, persistence, t1197, s0190, t1036_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## File Download Via Bitsadmin To A Suspicious Target Folder

### Description

Detects usage of bitsadmin downloading a file to a suspicious target folder

```yml
title: File Download Via Bitsadmin To A Suspicious Target Folder
id: 2ddef153-167b-4e89-86b6-757a9e65dcac
status: experimental
description: Detects usage of bitsadmin downloading a file to a suspicious target folder
references:
    - https://blog.netspi.com/15-ways-to-download-a-file/#bitsadmin
    - https://isc.sans.edu/diary/22264
    - https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/
    - https://blog.talosintelligence.com/breaking-the-silence-recent-truebot-activity/
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2022/06/28
modified: 2023/05/30
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
            - ':\Perflogs'
            - ':\ProgramData\'
            - ':\Temp\'
            - ':\Users\Public\'
            - ':\Windows\'
            - '\AppData\Local\Temp\'
            - '\AppData\Roaming\'
            - '\Desktop\'
            - '%ProgramData%'
            - '%public%'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high

```
