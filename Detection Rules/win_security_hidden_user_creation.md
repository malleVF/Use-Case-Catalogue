---
title: "Hidden Local User Creation"
status: "test"
created: "2021/05/03"
last_modified: "2022/10/09"
tags: [persistence, t1136_001, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## Hidden Local User Creation

### Description

Detects the creation of a local hidden user account which should not happen for event ID 4720.

```yml
title: Hidden Local User Creation
id: 7b449a5e-1db5-4dd0-a2dc-4e3a67282538
status: test
description: Detects the creation of a local hidden user account which should not happen for event ID 4720.
references:
    - https://twitter.com/SBousseaden/status/1387743867663958021
author: Christian Burkard (Nextron Systems)
date: 2021/05/03
modified: 2022/10/09
tags:
    - attack.persistence
    - attack.t1136.001
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4720
        TargetUserName|endswith: '$'
    condition: selection
falsepositives:
    - Unknown
level: high

```
