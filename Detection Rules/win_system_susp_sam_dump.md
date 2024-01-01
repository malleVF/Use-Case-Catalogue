---
title: "SAM Dump to AppData"
status: "test"
created: "2018/01/27"
last_modified: "2023/04/30"
tags: [credential_access, t1003_002, detection_rule]
logsrc_product: "windows"
logsrc_service: "system"
level: "high"
---

## SAM Dump to AppData

### Description

Detects suspicious SAM dump activity as cause by QuarksPwDump and other password dumpers

```yml
title: SAM Dump to AppData
id: 839dd1e8-eda8-4834-8145-01beeee33acd
status: test
description: Detects suspicious SAM dump activity as cause by QuarksPwDump and other password dumpers
author: Florian Roth (Nextron Systems)
date: 2018/01/27
modified: 2023/04/30
tags:
    - attack.credential_access
    - attack.t1003.002
logsource:
    product: windows
    service: system
    definition: The source of this type of event is Kernel-General
detection:
    selection:
        Provider_Name: Microsoft-Windows-Kernel-General
        EventID: 16
    keywords:
        '|all':
            - '\AppData\Local\Temp\SAM-'
            - '.dmp'
    condition: selection and keywords
falsepositives:
    - Unknown
level: high

```
