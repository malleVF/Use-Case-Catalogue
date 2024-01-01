---
title: "Renamed Vmnat.exe Execution"
status: "test"
created: "2022/09/09"
last_modified: "2023/02/03"
tags: [defense_evasion, t1574_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Renamed Vmnat.exe Execution

### Description

Detects renamed vmnat.exe or portable version that can be used for DLL side-loading

```yml
title: Renamed Vmnat.exe Execution
id: 7b4f794b-590a-4ad4-ba18-7964a2832205
status: test
description: Detects renamed vmnat.exe or portable version that can be used for DLL side-loading
references:
    - https://twitter.com/malmoeb/status/1525901219247845376
author: elhoim
date: 2022/09/09
modified: 2023/02/03
tags:
    - attack.defense_evasion
    - attack.t1574.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName: 'vmnat.exe'
    filter_rename:
        Image|endswith: 'vmnat.exe'
    condition: selection and not 1 of filter_*
falsepositives:
    - Unknown
level: high

```
