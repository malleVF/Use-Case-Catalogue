---
title: "Potential Persistence Via MyComputer Registry Keys"
status: "experimental"
created: "2022/08/09"
last_modified: "2023/08/17"
tags: [persistence, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Potential Persistence Via MyComputer Registry Keys

### Description

Detects modification to the "Default" value of the "MyComputer" key and subkeys to point to a custom binary that will be launched whenever the associated action is executed (see reference section for example)

```yml
title: Potential Persistence Via MyComputer Registry Keys
id: 8fbe98a8-8f9d-44f8-aa71-8c572e29ef06
status: experimental
description: Detects modification to the "Default" value of the "MyComputer" key and subkeys to point to a custom binary that will be launched whenever the associated action is executed (see reference section for example)
references:
    - https://www.hexacorn.com/blog/2017/01/18/beyond-good-ol-run-key-part-55/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/08/09
modified: 2023/08/17
tags:
    - attack.persistence
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer'
        TargetObject|endswith: '(Default)'
    condition: selection
falsepositives:
    - Unlikely but if you experience FPs add specific processes and locations you would like to monitor for
level: high

```