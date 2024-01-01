---
title: "Suspicious MSExchangeMailboxReplication ASPX Write"
status: "test"
created: "2022/02/25"
last_modified: ""
tags: [initial_access, t1190, persistence, t1505_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious MSExchangeMailboxReplication ASPX Write

### Description

Detects suspicious activity in which the MSExchangeMailboxReplication process writes .asp and .apsx files to disk, which could be a sign of ProxyShell exploitation

```yml
title: Suspicious MSExchangeMailboxReplication ASPX Write
id: 7280c9f3-a5af-45d0-916a-bc01cb4151c9
status: test
description: Detects suspicious activity in which the MSExchangeMailboxReplication process writes .asp and .apsx files to disk, which could be a sign of ProxyShell exploitation
references:
    - https://redcanary.com/blog/blackbyte-ransomware/
author: Florian Roth (Nextron Systems)
date: 2022/02/25
tags:
    - attack.initial_access
    - attack.t1190
    - attack.persistence
    - attack.t1505.003
logsource:
    product: windows
    category: file_event
detection:
    selection:
        Image|endswith: '\MSExchangeMailboxReplication.exe'
        TargetFilename|endswith:
            - '.aspx'
            - '.asp'
    condition: selection
falsepositives:
    - Unknown
level: high

```
