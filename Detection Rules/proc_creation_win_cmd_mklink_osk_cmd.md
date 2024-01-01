---
title: "Potential Privilege Escalation Using Symlink Between Osk and Cmd"
status: "test"
created: "2022/12/11"
last_modified: "2022/12/20"
tags: [privilege_escalation, persistence, t1546_008, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Potential Privilege Escalation Using Symlink Between Osk and Cmd

### Description

Detects the creation of a symbolic link between "cmd.exe" and the accessibility on-screen keyboard binary (osk.exe) using "mklink". This technique provides an elevated command prompt to the user from the login screen without the need to log in.

```yml
title: Potential Privilege Escalation Using Symlink Between Osk and Cmd
id: e9b61244-893f-427c-b287-3e708f321c6b
status: test
description: Detects the creation of a symbolic link between "cmd.exe" and the accessibility on-screen keyboard binary (osk.exe) using "mklink". This technique provides an elevated command prompt to the user from the login screen without the need to log in.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/5c1e6f1b4fafd01c8d1ece85f510160fc1275fbf/atomics/T1546.008/T1546.008.md
    - https://ss64.com/nt/mklink.html
author: frack113
date: 2022/12/11
modified: 2022/12/20
tags:
    - attack.privilege_escalation
    - attack.persistence
    - attack.t1546.008
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        - Image|endswith: '\cmd.exe'
        - OriginalFileName: 'Cmd.Exe'
    selection_cli:
        CommandLine|contains|all:
            - 'mklink'
            - '\osk.exe'
            - '\cmd.exe'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high

```
