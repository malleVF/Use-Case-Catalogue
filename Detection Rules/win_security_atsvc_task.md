---
title: "Remote Task Creation via ATSVC Named Pipe"
status: "test"
created: "2019/04/03"
last_modified: "2022/08/11"
tags: [lateral_movement, persistence, car_2013-05-004, car_2015-04-001, t1053_002, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "medium"
---

## Remote Task Creation via ATSVC Named Pipe

### Description

Detects remote task creation via at.exe or API interacting with ATSVC namedpipe

```yml
title: Remote Task Creation via ATSVC Named Pipe
id: f6de6525-4509-495a-8a82-1f8b0ed73a00
status: test
description: Detects remote task creation via at.exe or API interacting with ATSVC namedpipe
references:
    - https://blog.menasec.net/2019/03/threat-hunting-25-scheduled-tasks-for.html
author: Samir Bousseaden
date: 2019/04/03
modified: 2022/08/11
tags:
    - attack.lateral_movement
    - attack.persistence
    - car.2013-05-004
    - car.2015-04-001
    - attack.t1053.002
logsource:
    product: windows
    service: security
    definition: 'The advanced audit policy setting "Object Access > Audit Detailed File Share" must be configured for Success/Failure'
detection:
    selection:
        EventID: 5145
        ShareName: '\\\\\*\\IPC$' # looking for the string \\*\IPC$
        RelativeTargetName: atsvc
        Accesses|contains: 'WriteData'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
