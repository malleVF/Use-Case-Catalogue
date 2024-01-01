---
title: "Suspicious desktop.ini Action"
status: "test"
created: "2020/03/19"
last_modified: "2022/10/07"
tags: [persistence, t1547_009, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Suspicious desktop.ini Action

### Description

Detects unusual processes accessing desktop.ini, which can be leveraged to alter how Explorer displays a folder's content (i.e. renaming files) without changing them on disk.

```yml
title: Suspicious desktop.ini Action
id: 81315b50-6b60-4d8f-9928-3466e1022515
status: test
description: Detects unusual processes accessing desktop.ini, which can be leveraged to alter how Explorer displays a folder's content (i.e. renaming files) without changing them on disk.
references:
    - https://isc.sans.edu/forums/diary/Desktopini+as+a+postexploitation+tool/25912/
author: Maxime Thiebaut (@0xThiebaut), Tim Shelton (HAWK.IO)
date: 2020/03/19
modified: 2022/10/07
tags:
    - attack.persistence
    - attack.t1547.009
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith: '\desktop.ini'
    filter_generic:
        Image|startswith:
            - 'C:\Windows\'
            - 'C:\Program Files\'
            - 'C:\Program Files (x86)\'
    filter_jetbrains:
        Image|endswith: '\AppData\Local\JetBrains\Toolbox\bin\7z.exe'
        TargetFilename|contains: '\JetBrains\apps\'
    filter_upgrade:
        TargetFilename|startswith: 'C:\$WINDOWS.~BT\NewOS\'
    condition: selection and not 1 of filter_*
falsepositives:
    - Operations performed through Windows SCCM or equivalent
    - Read only access list authority
level: medium

```