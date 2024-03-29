---
title: "OMIGOD SCX RunAsProvider ExecuteShellCommand"
status: "test"
created: "2021/10/15"
last_modified: "2022/10/05"
tags: [privilege_escalation, initial_access, execution, t1068, t1190, t1203, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "high"
---

## OMIGOD SCX RunAsProvider ExecuteShellCommand

### Description

Rule to detect the use of the SCX RunAsProvider Invoke_ExecuteShellCommand to execute any UNIX/Linux command using the /bin/sh shell.
SCXcore, started as the Microsoft Operations Manager UNIX/Linux Agent, is now used in a host of products including
Microsoft Operations Manager, Microsoft Azure, and Microsoft Operations Management Suite.


```yml
title: OMIGOD SCX RunAsProvider ExecuteShellCommand
id: 21541900-27a9-4454-9c4c-3f0a4240344a
status: test
description: |
    Rule to detect the use of the SCX RunAsProvider Invoke_ExecuteShellCommand to execute any UNIX/Linux command using the /bin/sh shell.
    SCXcore, started as the Microsoft Operations Manager UNIX/Linux Agent, is now used in a host of products including
    Microsoft Operations Manager, Microsoft Azure, and Microsoft Operations Management Suite.
references:
    - https://www.wiz.io/blog/omigod-critical-vulnerabilities-in-omi-azure
    - https://github.com/Azure/Azure-Sentinel/pull/3059
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
date: 2021/10/15
modified: 2022/10/05
tags:
    - attack.privilege_escalation
    - attack.initial_access
    - attack.execution
    - attack.t1068
    - attack.t1190
    - attack.t1203
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        User: root
        LogonId: 0
        CurrentDirectory: '/var/opt/microsoft/scx/tmp'
        CommandLine|contains: '/bin/sh'
    condition: selection
falsepositives:
    - Legitimate use of SCX RunAsProvider Invoke_ExecuteShellCommand.
level: high

```
