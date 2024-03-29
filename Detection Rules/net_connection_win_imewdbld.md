---
title: "Network Connection Initiated By IMEWDBLD.EXE"
status: "test"
created: "2022/01/22"
last_modified: "2023/11/09"
tags: [command_and_control, t1105, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Network Connection Initiated By IMEWDBLD.EXE

### Description

Detects network connections initiated by IMEWDBLD. This might indicate potential abuse to download arbitrary files via this utility

```yml
title: Network Connection Initiated By IMEWDBLD.EXE
id: 8d7e392e-9b28-49e1-831d-5949c6281228
related:
    - id: 863218bd-c7d0-4c52-80cd-0a96c09f54af
      type: derived
status: test
description: Detects network connections initiated by IMEWDBLD. This might indicate potential abuse to download arbitrary files via this utility
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1105/T1105.md#atomic-test-10---windows---powershell-download
    - https://lolbas-project.github.io/lolbas/Binaries/IMEWDBLD/
author: frack113
date: 2022/01/22
modified: 2023/11/09
tags:
    - attack.command_and_control
    - attack.t1105
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Initiated: 'true'
        Image|endswith: '\IMEWDBLD.exe'
    condition: selection
falsepositives:
    - Unknown
# Note: Please reduce this to medium if you find legitimate connections
level: high

```
