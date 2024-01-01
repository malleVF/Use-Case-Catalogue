---
title: "Suspicious PsExec Execution"
status: "test"
created: "2019/04/03"
last_modified: "2022/08/11"
tags: [lateral_movement, t1021_002, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## Suspicious PsExec Execution

### Description

detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker uses a different psexec client other than sysinternal one

```yml
title: Suspicious PsExec Execution
id: c462f537-a1e3-41a6-b5fc-b2c2cef9bf82
status: test
description: detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker uses a different psexec client other than sysinternal one
references:
    - https://blog.menasec.net/2019/02/threat-hunting-3-detecting-psexec.html
author: Samir Bousseaden
date: 2019/04/03
modified: 2022/08/11
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
        RelativeTargetName|endswith:
            - '-stdin'
            - '-stdout'
            - '-stderr'
    filter:
        RelativeTargetName|startswith: 'PSEXESVC'
    condition: selection1 and not filter
falsepositives:
    - Unknown
level: high

```