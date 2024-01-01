---
title: "Admin User Remote Logon"
status: "test"
created: "2017/10/29"
last_modified: "2022/10/09"
tags: [lateral_movement, t1078_001, t1078_002, t1078_003, car_2016-04-005, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "low"
---

## Admin User Remote Logon

### Description

Detect remote login by Administrator user (depending on internal pattern).

```yml
title: Admin User Remote Logon
id: 0f63e1ef-1eb9-4226-9d54-8927ca08520a
status: test
description: Detect remote login by Administrator user (depending on internal pattern).
references:
    - https://car.mitre.org/wiki/CAR-2016-04-005
author: juju4
date: 2017/10/29
modified: 2022/10/09
tags:
    - attack.lateral_movement
    - attack.t1078.001
    - attack.t1078.002
    - attack.t1078.003
    - car.2016-04-005
logsource:
    product: windows
    service: security
    definition: 'Requirements: Identifiable administrators usernames (pattern or special unique character. ex: "Admin-*"), internal policy mandating use only as secondary account'
detection:
    selection:
        EventID: 4624
        LogonType: 10
        AuthenticationPackageName: Negotiate
        TargetUserName|startswith: 'Admin'
    condition: selection
falsepositives:
    - Legitimate administrative activity.
level: low

```
