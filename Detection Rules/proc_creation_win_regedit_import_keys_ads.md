---
title: "Imports Registry Key From an ADS"
status: "test"
created: "2020/10/12"
last_modified: "2023/02/03"
tags: [t1112, defense_evasion, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Imports Registry Key From an ADS

### Description

Detects the import of a alternate datastream to the registry with regedit.exe.

```yml
title: Imports Registry Key From an ADS
id: 0b80ade5-6997-4b1d-99a1-71701778ea61
related:
    - id: 73bba97f-a82d-42ce-b315-9182e76c57b1
      type: similar
status: test
description: Detects the import of a alternate datastream to the registry with regedit.exe.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Regedit/
    - https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f
author: Oddvar Moe, Sander Wiebing, oscd.community
date: 2020/10/12
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
            - '.reg'
        CommandLine|re: ':[^ \\]'
    filter:
        CommandLine|contains:
            - ' /e '
            - ' /a '
            - ' /c '
            - ' -e '
            - ' -a '
            - ' -c '
    condition: all of selection_* and not filter
fields:
    - ParentImage
    - CommandLine
falsepositives:
    - Unknown
level: high

```