---
title: "Unsigned Mfdetours.DLL Sideloading"
status: "experimental"
created: "2023/08/11"
last_modified: ""
tags: [defense_evasion, privilege_escalation, t1574_001, t1574_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Unsigned Mfdetours.DLL Sideloading

### Description

Detects DLL sideloading of unsigned "mfdetours.dll". Executing "mftrace.exe" can be abused to attach to an arbitrary process and force load any DLL named "mfdetours.dll" from the current directory of execution.

```yml
title: Unsigned Mfdetours.DLL Sideloading
id: 948a0953-f287-4806-bbcb-3b2e396df89f
related:
    - id: d2605a99-2218-4894-8fd3-2afb7946514d
      type: similar
status: experimental
description: Detects DLL sideloading of unsigned "mfdetours.dll". Executing "mftrace.exe" can be abused to attach to an arbitrary process and force load any DLL named "mfdetours.dll" from the current directory of execution.
references:
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/08/11
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1574.001
    - attack.t1574.002
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\mfdetours.dll'
    filter_main_legit_path:
        ImageLoaded|contains: ':\Program Files (x86)\Windows Kits\10\bin\'
        SignatureStatus: 'Valid'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unlikely
level: high

```