---
title: "OMIGOD SCX RunAsProvider ExecuteShellCommand - Auditd"
status: "test"
created: "2021/09/17"
last_modified: "2022/11/26"
tags: [privilege_escalation, initial_access, execution, t1068, t1190, t1203, detection_rule]
logsrc_product: "linux"
logsrc_service: "auditd"
level: "high"
---

## OMIGOD SCX RunAsProvider ExecuteShellCommand - Auditd

### Description

Rule to detect the use of the SCX RunAsProvider Invoke_ExecuteShellCommand to execute any UNIX/Linux command using the /bin/sh shell.
SCXcore, started as the Microsoft Operations Manager UNIX/Linux Agent, is now used in a host of products including Microsoft Operations Manager.
Microsoft Azure, and Microsoft Operations Management Suite.


```yml
title: OMIGOD SCX RunAsProvider ExecuteShellCommand - Auditd
id: 045b5f9c-49f7-4419-a236-9854fb3c827a
status: test
description: |
    Rule to detect the use of the SCX RunAsProvider Invoke_ExecuteShellCommand to execute any UNIX/Linux command using the /bin/sh shell.
    SCXcore, started as the Microsoft Operations Manager UNIX/Linux Agent, is now used in a host of products including Microsoft Operations Manager.
    Microsoft Azure, and Microsoft Operations Management Suite.
references:
    - https://www.wiz.io/blog/omigod-critical-vulnerabilities-in-omi-azure
    - https://github.com/Azure/Azure-Sentinel/pull/3059
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
date: 2021/09/17
modified: 2022/11/26
tags:
    - attack.privilege_escalation
    - attack.initial_access
    - attack.execution
    - attack.t1068
    - attack.t1190
    - attack.t1203
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: 'SYSCALL'
        syscall: 'execve'
        uid: 0
        cwd: '/var/opt/microsoft/scx/tmp'
        comm: 'sh'
    condition: selection
falsepositives:
    - Legitimate use of SCX RunAsProvider Invoke_ExecuteShellCommand.
level: high

```
