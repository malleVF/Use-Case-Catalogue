---
title: "Potential Persistence Using DebugPath"
status: "experimental"
created: "2022/07/27"
last_modified: "2023/08/17"
tags: [persistence, t1546_015, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Potential Persistence Using DebugPath

### Description

Detects potential persistence using Appx DebugPath

```yml
title: Potential Persistence Using DebugPath
id: df4dc653-1029-47ba-8231-3c44238cc0ae
status: experimental
description: Detects potential persistence using Appx DebugPath
references:
    - https://oddvar.moe/2018/09/06/persistence-using-universal-windows-platform-apps-appx/
    - https://github.com/rootm0s/WinPwnage
author: frack113
date: 2022/07/27
modified: 2023/08/17
tags:
    - attack.persistence
    - attack.t1546.015
logsource:
    category: registry_set
    product: windows
detection:
    selection_debug:
        TargetObject|contains: 'Classes\ActivatableClasses\Package\Microsoft.'
        TargetObject|endswith: '\DebugPath'
    selection_default:
        TargetObject|contains: '\Software\Microsoft\Windows\CurrentVersion\PackagedAppXDebug\Microsoft.'
        TargetObject|endswith: '\(Default)'
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: medium

```
