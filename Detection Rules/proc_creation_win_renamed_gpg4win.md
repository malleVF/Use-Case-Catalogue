---
title: "Renamed Gpg.EXE Execution"
status: "experimental"
created: "2023/08/09"
last_modified: ""
tags: [impact, t1486, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Renamed Gpg.EXE Execution

### Description

Detects the execution of a renamed "gpg.exe". Often used by ransomware and loaders to decrypt/encrypt data.

```yml
title: Renamed Gpg.EXE Execution
id: ec0722a3-eb5c-4a56-8ab2-bf6f20708592
status: experimental
description: Detects the execution of a renamed "gpg.exe". Often used by ransomware and loaders to decrypt/encrypt data.
references:
    - https://securelist.com/locked-out/68960/
author: Nasreddine Bencherchali (Nextron Systems), frack113
date: 2023/08/09
tags:
    - attack.impact
    - attack.t1486
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName: 'gpg.exe'
    filter_main_img:
        Image|endswith:
            - '\gpg.exe'
            - '\gpg2.exe'
    condition: selection and not 1 of filter_main_*
level: high

```
