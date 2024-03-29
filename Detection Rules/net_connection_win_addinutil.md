---
title: "Network Connection Initiated By AddinUtil.EXE"
status: "experimental"
created: "2023/09/18"
last_modified: ""
tags: [defense_evasion, t1218, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Network Connection Initiated By AddinUtil.EXE

### Description

Detects network connections made by the Add-In deployment cache updating utility (AddInutil.exe), which could indicate command and control communication.

```yml
title: Network Connection Initiated By AddinUtil.EXE
id: 5205613d-2a63-4412-a895-3a2458b587b3
status: experimental
description: Detects network connections made by the Add-In deployment cache updating utility (AddInutil.exe), which could indicate command and control communication.
references:
    - https://www.blue-prints.blog/content/blog/posts/lolbin/addinutil-lolbas.html
author: Michael McKinley (@McKinleyMike), Tony Latteri (@TheLatteri)
date: 2023/09/18
tags:
    - attack.defense_evasion
    - attack.t1218
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Initiated: 'true'
        Image|endswith: '\addinutil.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
