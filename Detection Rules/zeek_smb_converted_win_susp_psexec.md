---
title: "Suspicious PsExec Execution - Zeek"
status: "test"
created: "2020/04/02"
last_modified: "2022/12/27"
tags: [lateral_movement, t1021_002, detection_rule]
logsrc_product: "zeek"
logsrc_service: "smb_files"
level: "high"
---

## Suspicious PsExec Execution - Zeek

### Description

detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker uses a different psexec client other than sysinternal one

```yml
title: Suspicious PsExec Execution - Zeek
id: f1b3a22a-45e6-4004-afb5-4291f9c21166
related:
    - id: c462f537-a1e3-41a6-b5fc-b2c2cef9bf82
      type: derived
status: test
description: detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker uses a different psexec client other than sysinternal one
references:
    - https://blog.menasec.net/2019/02/threat-hunting-3-detecting-psexec.html
author: Samir Bousseaden, @neu5ron, Tim Shelton
date: 2020/04/02
modified: 2022/12/27
tags:
    - attack.lateral_movement
    - attack.t1021.002
logsource:
    product: zeek
    service: smb_files
detection:
    selection:
        path|contains|all:
            - '\\'
            - '\IPC$'
        name|endswith:
            - '-stdin'
            - '-stdout'
            - '-stderr'
    filter:
        name|startswith: 'PSEXESVC'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high

```
