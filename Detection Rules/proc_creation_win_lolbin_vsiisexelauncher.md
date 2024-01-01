---
title: "Use of VSIISExeLauncher.exe"
status: "test"
created: "2022/06/09"
last_modified: ""
tags: [defense_evasion, t1127, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Use of VSIISExeLauncher.exe

### Description

The "VSIISExeLauncher.exe" binary part of the Visual Studio/VS Code can be used to execute arbitrary binaries

```yml
title: Use of VSIISExeLauncher.exe
id: 18749301-f1c5-4efc-a4c3-276ff1f5b6f8
status: test
description: The "VSIISExeLauncher.exe" binary part of the Visual Studio/VS Code can be used to execute arbitrary binaries
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/VSIISExeLauncher/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/06/09
tags:
    - attack.defense_evasion
    - attack.t1127
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\VSIISExeLauncher.exe'
        - OriginalFileName: 'VSIISExeLauncher.exe'
    selection_cli:
        CommandLine|contains:
            - ' -p '
            - ' -a '
    condition: all of selection*
falsepositives:
    - Unknown
level: medium

```