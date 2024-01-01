---
title: "Suspicious Processes Spawned by WinRM"
status: "test"
created: "2021/05/20"
last_modified: "2022/07/14"
tags: [t1190, initial_access, persistence, privilege_escalation, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious Processes Spawned by WinRM

### Description

Detects suspicious processes including shells spawnd from WinRM host process

```yml
title: Suspicious Processes Spawned by WinRM
id: 5cc2cda8-f261-4d88-a2de-e9e193c86716
status: test
description: Detects suspicious processes including shells spawnd from WinRM host process
author: Andreas Hunkeler (@Karneades), Markus Neis
date: 2021/05/20
modified: 2022/07/14
tags:
    - attack.t1190
    - attack.initial_access
    - attack.persistence
    - attack.privilege_escalation
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\wsmprovhost.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\sh.exe'
            - '\bash.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\wsl.exe'
            - '\schtasks.exe'
            - '\certutil.exe'
            - '\whoami.exe'
            - '\bitsadmin.exe'
    condition: selection
falsepositives:
    - Legitimate WinRM usage
level: high

```
