---
title: "Windows Kernel Debugger Execution"
status: "experimental"
created: "2023/05/15"
last_modified: ""
tags: [defense_evasion, privilege_escalation, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Windows Kernel Debugger Execution

### Description

Detects execution of the Windows Kernel Debugger "kd.exe".

```yml
title: Windows Kernel Debugger Execution
id: 27ee9438-90dc-4bef-904b-d3ef927f5e7e
status: experimental
description: Detects execution of the Windows Kernel Debugger "kd.exe".
references:
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/05/15
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\kd.exe'
        - OriginalFileName: 'kd.exe'
    condition: selection
falsepositives:
    - Rare occasions of legitimate cases where kernel debugging is necessary in production. Investigation is required
level: high

```
