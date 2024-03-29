---
title: "Register new Logon Process by Rubeus"
status: "test"
created: "2019/10/24"
last_modified: "2022/10/09"
tags: [lateral_movement, privilege_escalation, t1558_003, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## Register new Logon Process by Rubeus

### Description

Detects potential use of Rubeus via registered new trusted logon process

```yml
title: Register new Logon Process by Rubeus
id: 12e6d621-194f-4f59-90cc-1959e21e69f7
status: test
description: Detects potential use of Rubeus via registered new trusted logon process
references:
    - https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1
author: Roberto Rodriguez (source), Ilyas Ochkov (rule), oscd.community
date: 2019/10/24
modified: 2022/10/09
tags:
    - attack.lateral_movement
    - attack.privilege_escalation
    - attack.t1558.003
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4611
        LogonProcessName: 'User32LogonProcesss'
    condition: selection
falsepositives:
    - Unknown
level: high

```
