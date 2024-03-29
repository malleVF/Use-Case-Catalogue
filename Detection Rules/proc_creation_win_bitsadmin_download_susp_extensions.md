---
title: "File With Suspicious Extension Downloaded Via Bitsadmin"
status: "experimental"
created: "2022/06/28"
last_modified: "2023/05/30"
tags: [defense_evasion, persistence, t1197, s0190, t1036_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## File With Suspicious Extension Downloaded Via Bitsadmin

### Description

Detects usage of bitsadmin downloading a file with a suspicious extension

```yml
title: File With Suspicious Extension Downloaded Via Bitsadmin
id: 5b80a791-ad9b-4b75-bcc1-ad4e1e89c200
status: experimental
description: Detects usage of bitsadmin downloading a file with a suspicious extension
references:
    - https://blog.netspi.com/15-ways-to-download-a-file/#bitsadmin
    - https://isc.sans.edu/diary/22264
    - https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/
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
    selection_extension:
        CommandLine|contains:
            - '.7z'
            - '.asax'
            - '.ashx'
            - '.asmx'
            - '.asp'
            - '.aspx'
            - '.bat'
            - '.cfm'
            - '.cgi'
            - '.chm'
            - '.cmd'
            - '.dll'
            - '.gif'
            - '.jpeg'
            - '.jpg'
            - '.jsp'
            - '.jspx'
            - '.log'
            - '.png'
            - '.ps1'
            - '.psm1'
            - '.rar'
            - '.scf'
            - '.sct'
            - '.txt'
            - '.vbe'
            - '.vbs'
            - '.war'
            - '.wsf'
            - '.wsh'
            - '.xll'
            - '.zip'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high

```
