---
title: "Remote PowerShell Session Host Process (WinRM)"
status: "test"
created: "2019/09/12"
last_modified: "2022/10/09"
tags: [execution, t1059_001, t1021_006, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Remote PowerShell Session Host Process (WinRM)

### Description

Detects remote PowerShell sections by monitoring for wsmprovhost (WinRM host process) as a parent or child process (sign of an active PowerShell remote session).

```yml
title: Remote PowerShell Session Host Process (WinRM)
id: 734f8d9b-42b8-41b2-bcf5-abaf49d5a3c8
status: test
description: Detects remote PowerShell sections by monitoring for wsmprovhost (WinRM host process) as a parent or child process (sign of an active PowerShell remote session).
references:
    - https://threathunterplaybook.com/hunts/windows/190511-RemotePwshExecution/notebook.html
author: Roberto Rodriguez @Cyb3rWard0g
date: 2019/09/12
modified: 2022/10/09
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1021.006
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\wsmprovhost.exe'
        - ParentImage|endswith: '\wsmprovhost.exe'
    condition: selection
fields:
    - ComputerName
    - User
    - CommandLine
falsepositives:
    - Legitimate usage of remote Powershell, e.g. for monitoring purposes.
level: medium

```