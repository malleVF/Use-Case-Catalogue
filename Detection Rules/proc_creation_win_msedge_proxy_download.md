---
title: "Arbitrary File Download Via MSEDGE_PROXY.EXE"
status: "experimental"
created: "2023/11/09"
last_modified: ""
tags: [defense_evasion, execution, t1218, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Arbitrary File Download Via MSEDGE_PROXY.EXE

### Description

Detects usage of "msedge_proxy.exe" to download arbitrary files

```yml
title: Arbitrary File Download Via MSEDGE_PROXY.EXE
id: e84d89c4-f544-41ca-a6af-4b92fd38b023
status: experimental
description: Detects usage of "msedge_proxy.exe" to download arbitrary files
references:
    - https://lolbas-project.github.io/lolbas/Binaries/msedge_proxy/
author: Swachchhanda Shrawan Poudel
date: 2023/11/09
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\msedge_proxy.exe'
        - OriginalFileName: 'msedge_proxy.exe'
    selection_cli:
        CommandLine|contains:
            - 'http://'
            - 'https://'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium

```
