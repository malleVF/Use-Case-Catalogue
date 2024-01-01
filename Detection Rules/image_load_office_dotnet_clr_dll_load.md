---
title: "CLR DLL Loaded Via Office Applications"
status: "test"
created: "2020/02/19"
last_modified: "2023/03/29"
tags: [execution, t1204_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## CLR DLL Loaded Via Office Applications

### Description

Detects CLR DLL being loaded by an Office Product

```yml
title: CLR DLL Loaded Via Office Applications
id: d13c43f0-f66b-4279-8b2c-5912077c1780
status: test
description: Detects CLR DLL being loaded by an Office Product
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
            - '\outlook.exe'
            - '\onenote.exe'
            - '\onenoteim.exe' # Just in case
            - '\powerpnt.exe'
            - '\winword.exe'
        ImageLoaded|contains: '\clr.dll'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
