---
title: "Remote DLL Load Via Rundll32.EXE"
status: "experimental"
created: "2023/09/18"
last_modified: ""
tags: [execution, t1204_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Remote DLL Load Via Rundll32.EXE

### Description

Detects a remote DLL load event via "rundll32.exe".

```yml
title: Remote DLL Load Via Rundll32.EXE
id: f40017b3-cb2e-4335-ab5d-3babf679c1de
status: experimental
description: Detects a remote DLL load event via "rundll32.exe".
references:
    - https://github.com/gabe-k/themebleed
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/09/18
tags:
    - attack.execution
    - attack.t1204.002
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\rundll32.exe'
        ImageLoaded|startswith: '\\\\'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
