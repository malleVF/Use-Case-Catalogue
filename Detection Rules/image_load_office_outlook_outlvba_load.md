---
title: "Microsoft VBA For Outlook Addin Loaded Via Outlook"
status: "test"
created: "2023/02/08"
last_modified: ""
tags: [execution, t1204_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Microsoft VBA For Outlook Addin Loaded Via Outlook

### Description

Detects outlvba (Microsoft VBA for Outlook Addin) DLL being loaded by the outlook process

```yml
title: Microsoft VBA For Outlook Addin Loaded Via Outlook
id: 9a0b8719-cd3c-4f0a-90de-765a4cb3f5ed
status: test
description: Detects outlvba (Microsoft VBA for Outlook Addin) DLL being loaded by the outlook process
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=58
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/02/08
tags:
    - attack.execution
    - attack.t1204.002
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\outlook.exe'
        ImageLoaded|startswith: '\outlvba.dll'
    condition: selection
falsepositives:
    - Legitimate macro usage. Add the appropriate filter according to your environment
level: high

```
