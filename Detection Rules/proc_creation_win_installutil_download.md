---
title: "File Download Via InstallUtil.EXE"
status: "test"
created: "2022/08/19"
last_modified: "2023/11/09"
tags: [defense_evasion, t1218, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## File Download Via InstallUtil.EXE

### Description

Detects use of .NET InstallUtil.exe in order to download arbitrary files. The files will be written to "%LOCALAPPDATA%\Microsoft\Windows\INetCache\IE\"


```yml
title: File Download Via InstallUtil.EXE
id: 75edd216-1939-4c73-8d61-7f3a0d85b5cc
status: test
description: |
    Detects use of .NET InstallUtil.exe in order to download arbitrary files. The files will be written to "%LOCALAPPDATA%\Microsoft\Windows\INetCache\IE\"
references:
    - https://github.com/LOLBAS-Project/LOLBAS/pull/239
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/08/19
modified: 2023/11/09
tags:
    - attack.defense_evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\InstallUtil.exe'
        - OriginalFileName: 'InstallUtil.exe'
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
