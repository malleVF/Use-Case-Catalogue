---
title: "Remote Service Activity via SVCCTL Named Pipe"
status: "test"
created: "2019/04/03"
last_modified: "2022/08/11"
tags: [lateral_movement, persistence, t1021_002, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "medium"
---

## Remote Service Activity via SVCCTL Named Pipe

### Description

Detects remote service activity via remote access to the svcctl named pipe

```yml
title: Remote Service Activity via SVCCTL Named Pipe
id: 586a8d6b-6bfe-4ad9-9d78-888cd2fe50c3
status: test
description: Detects remote service activity via remote access to the svcctl named pipe
references:
    - https://blog.menasec.net/2019/03/threat-hunting-26-remote-windows.html
author: Samir Bousseaden
date: 2019/04/03
modified: 2022/08/11
tags:
    - attack.lateral_movement
    - attack.persistence
    - attack.t1021.002
logsource:
    product: windows
    service: security
    definition: 'The advanced audit policy setting "Object Access > Audit Detailed File Share" must be configured for Success/Failure'
detection:
    selection:
        EventID: 5145
        ShareName: '\\\\\*\\IPC$' # looking for the string \\*\IPC$
        RelativeTargetName: svcctl
        Accesses|contains: 'WriteData'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
