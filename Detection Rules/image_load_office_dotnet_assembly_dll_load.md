---
title: "DotNET Assembly DLL Loaded Via Office Application"
status: "test"
created: "2020/02/19"
last_modified: "2023/03/29"
tags: [execution, t1204_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## DotNET Assembly DLL Loaded Via Office Application

### Description

Detects any assembly DLL being loaded by an Office Product

```yml
title: DotNET Assembly DLL Loaded Via Office Application
id: ff0f2b05-09db-4095-b96d-1b75ca24894a
status: test
description: Detects any assembly DLL being loaded by an Office Product
references:
    - https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16
author: Antonlovesdnb
date: 2020/02/19
modified: 2023/03/29
tags:
    - attack.execution
    - attack.t1204.002
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith:
            - '\excel.exe'
            - '\mspub.exe'
            - '\onenote.exe'
            - '\onenoteim.exe' # Just in case
            - '\outlook.exe'
            - '\powerpnt.exe'
            - '\winword.exe'
        ImageLoaded|startswith: 'C:\Windows\assembly\'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
