---
title: "Arbitrary File Download Via MSPUB.EXE"
status: "experimental"
created: "2022/08/19"
last_modified: "2023/02/08"
tags: [defense_evasion, execution, t1218, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Arbitrary File Download Via MSPUB.EXE

### Description

Detects usage of "MSPUB" (Microsoft Publisher) to download arbitrary files

```yml
title: Arbitrary File Download Via MSPUB.EXE
id: 3b3c7f55-f771-4dd6-8a6e-08d057a17caf
status: experimental
description: Detects usage of "MSPUB" (Microsoft Publisher) to download arbitrary files
references:
    - https://github.com/LOLBAS-Project/LOLBAS/pull/238/files
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/08/19
modified: 2023/02/08
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\MSPUB.exe'
        - OriginalFileName: 'MSPUB.exe'
    selection_cli:
        CommandLine|contains:
            - 'ftp://'
            - 'http://'
            - 'https://'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium

```
