---
title: "Suspicious Greedy Compression Using Rar.EXE"
status: "experimental"
created: "2022/12/15"
last_modified: "2023/12/11"
tags: [execution, t1059, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious Greedy Compression Using Rar.EXE

### Description

Detects RAR usage that creates an archive from a suspicious folder, either a system folder or one of the folders often used by attackers for staging purposes

```yml
title: Suspicious Greedy Compression Using Rar.EXE
id: afe52666-401e-4a02-b4ff-5d128990b8cb
status: experimental
description: Detects RAR usage that creates an archive from a suspicious folder, either a system folder or one of the folders often used by attackers for staging purposes
references:
    - https://decoded.avast.io/martinchlumecky/png-steganography
author: X__Junior (Nextron Systems), Florian Roth (Nextron Systems)
date: 2022/12/15
modified: 2023/12/11
tags:
    - attack.execution
    - attack.t1059
logsource:
    product: windows
    category: process_creation
detection:
    # Example : rar.exe a -m5 -r -y -ta20210204000000 -hp1qazxcde32ws -v2560k Asia1Dpt-PC-c.rar c:\\*.doc c:\\*.docx c:\\*.xls c:\\*.xlsx c:\\*.pdf c:\\*.ppt c:\\*.pptx c:\\*.jpg c:\\*.txt >nul
    selection_opt_1:
        - Image|endswith: '\rar.exe'
        - Description: 'Command line RAR'
    selection_opt_2:
        CommandLine|contains:
            - '.exe a '
            - ' a -m'
    selection_cli_flags:
        CommandLine|contains|all:
            - ' -hp' # password
            - ' -r ' # recursive
    selection_cli_folders:
        CommandLine|contains:
            - ' :\\\*.'
            - ' :\\\\\*.'
            - ' :\Users\Public\'
            - ' %public%'
            - ' :\Windows\'
            - ' :\PerfLogs\'
            - ' :\Temp'
            - ' :\$Recycle.bin\'
    condition: 1 of selection_opt_* and all of selection_cli_*
falsepositives:
    - Unknown
level: high

```
