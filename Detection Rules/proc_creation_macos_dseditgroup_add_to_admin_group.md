---
title: "User Added To Admin Group Via DseditGroup"
status: "experimental"
created: "2023/08/22"
last_modified: ""
tags: [initial_access, privilege_escalation, t1078_003, detection_rule]
logsrc_product: "macos"
logsrc_service: ""
level: "medium"
---

## User Added To Admin Group Via DseditGroup

### Description

Detects attempts to create and/or add an account to the admin group, thus granting admin privileges.

```yml
title: User Added To Admin Group Via DseditGroup
id: 5d0fdb62-f225-42fb-8402-3dfe64da468a
status: experimental
description: Detects attempts to create and/or add an account to the admin group, thus granting admin privileges.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.003/T1078.003.md#atomic-test-5---add-a-newexisting-user-to-the-admin-group-using-dseditgroup-utility---macos
    - https://ss64.com/osx/dseditgroup.html
author: Sohan G (D4rkCiph3r)
date: 2023/08/22
tags:
    - attack.initial_access
    - attack.privilege_escalation
    - attack.t1078.003
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|endswith: '/dseditgroup'
        CommandLine|contains|all:
            - ' -o edit ' # edit operation
            - ' -a ' # username
            - ' -t user'
            - 'admin' # Group name
    condition: selection
falsepositives:
    - Legitimate administration activities
level: medium

```
