---
title: "New BgInfo.EXE Custom WMI Query Registry Configuration"
status: "experimental"
created: "2023/08/16"
last_modified: ""
tags: [defense_evasion, t1112, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## New BgInfo.EXE Custom WMI Query Registry Configuration

### Description

Detects setting of a new registry value related to BgInfo configuration, which can be abused to execute custom WMI query via "BgInfo.exe"

```yml
title: New BgInfo.EXE Custom WMI Query Registry Configuration
id: cd277474-5c52-4423-a52b-ac2d7969902f
related:
    - id: 992dd79f-dde8-4bb0-9085-6350ba97cfb3
      type: similar
status: experimental
description: Detects setting of a new registry value related to BgInfo configuration, which can be abused to execute custom WMI query via "BgInfo.exe"
references:
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/08/16
tags:
    - attack.defense_evasion
    - attack.t1112
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        EventType: SetValue
        TargetObject|contains: '\Software\Winternals\BGInfo\UserFields\'
        Details|startswith: '6' # WMI
    condition: selection
falsepositives:
    - Legitimate WMI query
level: medium

```