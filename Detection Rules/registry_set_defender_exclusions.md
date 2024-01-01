---
title: "Windows Defender Exclusions Added - Registry"
status: "test"
created: "2021/07/06"
last_modified: "2023/08/17"
tags: [defense_evasion, t1562_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Windows Defender Exclusions Added - Registry

### Description

Detects the Setting of Windows Defender Exclusions

```yml
title: Windows Defender Exclusions Added - Registry
id: a982fc9c-6333-4ffb-a51d-addb04e8b529
related:
    - id: 1321dc4e-a1fe-481d-a016-52c45f0c8b4f
      type: derived
status: test
description: Detects the Setting of Windows Defender Exclusions
references:
    - https://twitter.com/_nullbind/status/1204923340810543109
author: Christian Burkard (Nextron Systems)
date: 2021/07/06
modified: 2023/08/17
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    product: windows
    category: registry_set
detection:
    selection2:
        TargetObject|contains: '\Microsoft\Windows Defender\Exclusions'
    condition: selection2
falsepositives:
    - Administrator actions
level: medium

```
