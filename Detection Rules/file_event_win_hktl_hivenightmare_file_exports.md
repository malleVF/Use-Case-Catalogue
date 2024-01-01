---
title: "Typical HiveNightmare SAM File Export"
status: "test"
created: "2021/07/23"
last_modified: "2022/10/09"
tags: [credential_access, t1552_001, cve_2021_36934, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Typical HiveNightmare SAM File Export

### Description

Detects files written by the different tools that exploit HiveNightmare

```yml
title: Typical HiveNightmare SAM File Export
id: 6ea858a8-ba71-4a12-b2cc-5d83312404c7
status: test
description: Detects files written by the different tools that exploit HiveNightmare
references:
    - https://github.com/GossiTheDog/HiveNightmare
    - https://github.com/FireFart/hivenightmare/
    - https://github.com/WiredPulse/Invoke-HiveNightmare
    - https://twitter.com/cube0x0/status/1418920190759378944
author: Florian Roth (Nextron Systems)
date: 2021/07/23
modified: 2022/10/09
tags:
    - attack.credential_access
    - attack.t1552.001
    - cve.2021.36934
logsource:
    product: windows
    category: file_event
detection:
    selection:
        - TargetFilename|contains:
              - '\hive_sam_'  # Go version
              - '\SAM-2021-'  # C++ version
              - '\SAM-2022-'  # C++ version
              - '\SAM-2023-'  # C++ version
              - '\SAM-haxx'   # Early C++ versions
              - '\Sam.save'   # PowerShell version
        - TargetFilename: 'C:\windows\temp\sam'  # C# version of HiveNightmare
    condition: selection
falsepositives:
    - Files that accidentally contain these strings
level: high

```
