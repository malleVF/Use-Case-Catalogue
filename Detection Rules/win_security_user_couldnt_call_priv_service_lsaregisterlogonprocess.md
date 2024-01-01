---
title: "User Couldn't Call a Privileged Service 'LsaRegisterLogonProcess'"
status: "test"
created: "2019/10/24"
last_modified: "2022/12/25"
tags: [lateral_movement, privilege_escalation, t1558_003, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## User Couldn't Call a Privileged Service 'LsaRegisterLogonProcess'

### Description

The 'LsaRegisterLogonProcess' function verifies that the application making the function call is a logon process by checking that it has the SeTcbPrivilege privilege set. Possible Rubeus tries to get a handle to LSA.

```yml
title: User Couldn't Call a Privileged Service 'LsaRegisterLogonProcess'
id: 6daac7fc-77d1-449a-a71a-e6b4d59a0e54
status: test
description: The 'LsaRegisterLogonProcess' function verifies that the application making the function call is a logon process by checking that it has the SeTcbPrivilege privilege set. Possible Rubeus tries to get a handle to LSA.
references:
    - https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1
author: Roberto Rodriguez (source), Ilyas Ochkov (rule), oscd.community
date: 2019/10/24
modified: 2022/12/25
tags:
    - attack.lateral_movement
    - attack.privilege_escalation
    - attack.t1558.003
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4673
        Service: 'LsaRegisterLogonProcess()'
        Keywords: '0x8010000000000000'     # failure
    condition: selection
falsepositives:
    - Unknown
level: high

```
