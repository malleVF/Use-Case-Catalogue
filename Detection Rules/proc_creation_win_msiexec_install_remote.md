---
title: "Suspicious Msiexec Quiet Install From Remote Location"
status: "test"
created: "2022/10/28"
last_modified: ""
tags: [defense_evasion, t1218_007, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Suspicious Msiexec Quiet Install From Remote Location

### Description

Detects usage of Msiexec.exe to install packages hosted remotely quietly

```yml
title: Suspicious Msiexec Quiet Install From Remote Location
id: 8150732a-0c9d-4a99-82b9-9efb9b90c40c
related:
    - id: f7b5f842-a6af-4da5-9e95-e32478f3cd2f
      type: similar
status: test
description: Detects usage of Msiexec.exe to install packages hosted remotely quietly
references:
    - https://www.microsoft.com/en-us/security/blog/2022/10/27/raspberry-robin-worm-part-of-larger-ecosystem-facilitating-pre-ransomware-activity/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/10/28
tags:
    - attack.defense_evasion
    - attack.t1218.007
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\msiexec.exe'
        - OriginalFileName: 'msiexec.exe'
    selection_cli:
        # Note that there is no space before and after the arguments because it's possible to write a commandline as such
        # Example: msiexec -q/i [MSI Package]
        CommandLine|contains:
            - '/i'
            - '-i'
            - '/package'
            - '-package'
            - '/a'
            - '-a'
            - '/j'
            - '-j'
    selection_quiet:
        CommandLine|contains:
            - '/q'
            - '-q'
    selection_remote:
        CommandLine|contains:
            - 'http'
            - '\\\\'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium

```
