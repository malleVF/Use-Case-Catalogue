---
title: "Imports Registry Key From a File"
status: "test"
created: "2020/10/07"
last_modified: "2023/02/03"
tags: [t1112, defense_evasion, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Imports Registry Key From a File

### Description

Detects the import of the specified file to the registry with regedit.exe.

```yml
title: Imports Registry Key From a File
id: 73bba97f-a82d-42ce-b315-9182e76c57b1
related:
    - id: 0b80ade5-6997-4b1d-99a1-71701778ea61
      type: similar
status: test
description: Detects the import of the specified file to the registry with regedit.exe.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Regedit/
    - https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f
author: Oddvar Moe, Sander Wiebing, oscd.community
date: 2020/10/07
modified: 2023/02/03
tags:
    - attack.t1112
    - attack.defense_evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\regedit.exe'
        - OriginalFileName: 'REGEDIT.EXE'
    selection_cli:
        CommandLine|contains:
            - ' /i '
            - ' /s '
            - '.reg'
    filter_1:
        CommandLine|contains:
            - ' /e '
            - ' /a '
            - ' /c '
            - ' -e '
            - ' -a '
            - ' -c '
    filter_2:
        CommandLine|re: ':[^ \\]'     # to avoid intersection with ADS rule
    condition: all of selection_* and not all of filter_*
fields:
    - ParentImage
    - CommandLine
falsepositives:
    - Legitimate import of keys
    - Evernote
level: medium

```
