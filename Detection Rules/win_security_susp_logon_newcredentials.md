---
title: "Outgoing Logon with New Credentials"
status: "test"
created: "2022/04/06"
last_modified: ""
tags: [defense_evasion, lateral_movement, t1550, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "low"
---

## Outgoing Logon with New Credentials

### Description

Detects logon events that specify new credentials

```yml
title: Outgoing Logon with New Credentials
id: def8b624-e08f-4ae1-8612-1ba21190da6b
status: test
description: Detects logon events that specify new credentials
references:
    - https://go.recordedfuture.com/hubfs/reports/mtp-2021-0914.pdf
author: Max Altgelt (Nextron Systems)
date: 2022/04/06
tags:
    - attack.defense_evasion
    - attack.lateral_movement
    - attack.t1550
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 9
    condition: selection
falsepositives:
    - Legitimate remote administration activity
level: low

```
