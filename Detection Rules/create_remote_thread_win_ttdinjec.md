---
title: "Remote Thread Creation Ttdinject.exe Proxy"
status: "test"
created: "2022/05/16"
last_modified: "2022/06/02"
tags: [defense_evasion, t1127, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Remote Thread Creation Ttdinject.exe Proxy

### Description

Detects a remote thread creation of Ttdinject.exe used as proxy

```yml
title: Remote Thread Creation Ttdinject.exe Proxy
id: c15e99a3-c474-48ab-b9a7-84549a7a9d16
status: test
description: Detects a remote thread creation of Ttdinject.exe used as proxy
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Ttdinject/
author: frack113
date: 2022/05/16
modified: 2022/06/02
tags:
    - attack.defense_evasion
    - attack.t1127
logsource:
    product: windows
    category: create_remote_thread
detection:
    selection:
        SourceImage|endswith: '\ttdinject.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```
