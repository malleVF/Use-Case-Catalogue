---
title: "Remote Access Tool - LogMeIn Execution"
status: "test"
created: "2022/02/11"
last_modified: "2023/03/05"
tags: [command_and_control, t1219, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Remote Access Tool - LogMeIn Execution

### Description

An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)


```yml
title: Remote Access Tool - LogMeIn Execution
id: d85873ef-a0f8-4c48-a53a-6b621f11729d
status: test
description: |
    An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
    These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
    Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1219/T1219.md#atomic-test-3---logmein-files-detected-test-on-windows
author: frack113
date: 2022/02/11
modified: 2023/03/05
tags:
    - attack.command_and_control
    - attack.t1219
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Description: LMIGuardianSvc
        - Product: LMIGuardianSvc
        - Company: LogMeIn, Inc.
    condition: selection
falsepositives:
    - Legitimate use
level: medium

```