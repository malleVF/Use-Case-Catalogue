---
title: "New RUN Key Pointing to Suspicious Folder"
status: "experimental"
created: "2018/08/25"
last_modified: "2023/12/11"
tags: [persistence, t1547_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## New RUN Key Pointing to Suspicious Folder

### Description

Detects suspicious new RUN key element pointing to an executable in a suspicious folder

```yml
title: New RUN Key Pointing to Suspicious Folder
id: 02ee49e2-e294-4d0f-9278-f5b3212fc588
status: experimental
description: Detects suspicious new RUN key element pointing to an executable in a suspicious folder
references:
    - https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html
author: Florian Roth (Nextron Systems), Markus Neis, Sander Wiebing
date: 2018/08/25
modified: 2023/12/11
tags:
    - attack.persistence
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection_target:
        TargetObject|contains:
            - '\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\'
            - '\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\'
    selection_details:
        - Details|contains:
              - ':\$Recycle.bin\'
              - ':\Temp\'
              - ':\Users\Default\'
              - ':\Users\Desktop\'
              - ':\Users\Public\'
              - ':\Windows\Temp\'
              - '\AppData\Local\Temp\'
              - '%temp%\'
              - '%tmp%\'
        - Details|startswith:
              - '%Public%\'
              - 'wscript'
              - 'cscript'
    condition: all of selection_*
fields:
    - Image
falsepositives:
    - Software using weird folders for updates
level: high

```
