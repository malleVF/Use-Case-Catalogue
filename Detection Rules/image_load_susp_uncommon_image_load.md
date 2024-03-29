---
title: "Possible Process Hollowing Image Loading"
status: "test"
created: "2018/01/07"
last_modified: "2021/11/27"
tags: [defense_evasion, t1574_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Possible Process Hollowing Image Loading

### Description

Detects Loading of samlib.dll, WinSCard.dll from untypical process e.g. through process hollowing by Mimikatz

```yml
title: Possible Process Hollowing Image Loading
id: e32ce4f5-46c6-4c47-ba69-5de3c9193cd7
status: test
description: Detects Loading of samlib.dll, WinSCard.dll from untypical process e.g. through process hollowing by Mimikatz
references:
    - https://web.archive.org/web/20220815065318/https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for.html
author: Markus Neis
date: 2018/01/07
modified: 2021/11/27
tags:
    - attack.defense_evasion
    - attack.t1574.002
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\notepad.exe'
        ImageLoaded|endswith:
            - '\samlib.dll'
            - '\WinSCard.dll'
    condition: selection
falsepositives:
    - Very likely, needs more tuning
level: high

```
