---
title: "VBA DLL Loaded Via Office Application"
status: "test"
created: "2020/02/19"
last_modified: "2023/02/10"
tags: [execution, t1204_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## VBA DLL Loaded Via Office Application

### Description

Detects VB DLL's loaded by an office application. Which could indicate the presence of VBA Macros.

```yml
title: VBA DLL Loaded Via Office Application
id: e6ce8457-68b1-485b-9bdd-3c2b5d679aa9
status: test
description: Detects VB DLL's loaded by an office application. Which could indicate the presence of VBA Macros.
references:
    - https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16
author: Antonlovesdnb
date: 2020/02/19
modified: 2023/02/10
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
        ImageLoaded|endswith:
            - '\VBE7.DLL'
            - '\VBEUI.DLL'
            - '\VBE7INTL.DLL'
    condition: selection
falsepositives:
    - Legitimate macro usage. Add the appropriate filter according to your environment
level: high

```