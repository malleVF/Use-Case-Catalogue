---
title: "Impacket PsExec Execution"
status: "test"
created: "2020/12/14"
last_modified: "2022/09/22"
tags: [lateral_movement, t1021_002, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## Impacket PsExec Execution

### Description

Detects execution of Impacket's psexec.py.

```yml
title: Impacket PsExec Execution
id: 32d56ea1-417f-44ff-822b-882873f5f43b
status: test
description: Detects execution of Impacket's psexec.py.
references:
    - https://blog.menasec.net/2019/02/threat-hunting-3-detecting-psexec.html
author: Bhabesh Raj
date: 2020/12/14
modified: 2022/09/22
tags:
    - attack.lateral_movement
    - attack.t1021.002
logsource:
    product: windows
    service: security
    definition: 'The advanced audit policy setting "Object Access > Audit Detailed File Share" must be configured for Success/Failure'
detection:
    selection1:
        EventID: 5145
        ShareName: '\\\\\*\\IPC$' # looking for the string \\*\IPC$
        RelativeTargetName|contains:
            - 'RemCom_stdin'
            - 'RemCom_stdout'
            - 'RemCom_stderr'
    condition: selection1
falsepositives:
    - Unknown
level: high

```
