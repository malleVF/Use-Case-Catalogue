---
title: "Remote Access Tool - ScreenConnect Remote Command Execution"
status: "experimental"
created: "2023/10/10"
last_modified: ""
tags: [execution, t1059_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Remote Access Tool - ScreenConnect Remote Command Execution

### Description

Detects the execution of a system command via the ScreenConnect RMM service.

```yml
title: Remote Access Tool - ScreenConnect Remote Command Execution
id: b1f73849-6329-4069-bc8f-78a604bb8b23
status: experimental
description: Detects the execution of a system command via the ScreenConnect RMM service.
references:
    - https://github.com/SigmaHQ/sigma/pull/4467
author: Ali Alwashali
date: 2023/10/10
tags:
    - attack.execution
    - attack.t1059.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\ScreenConnect.ClientService.exe'
    selection_img:
        - Image|endswith: '\cmd.exe'
        - OriginalFileName: 'Cmd.Exe'
    selection_cli:
        # Example:
        #   CommandLine: "cmd.exe" /c "C:\Windows\TEMP\ScreenConnect\23.6.8.8644\3c41d689-bbf5-4216-b2f4-ba8fd6192c25run.cmd"
        CommandLine|contains: '\TEMP\ScreenConnect\'
    condition: all of selection_*
falsepositives:
    - Legitimate use of ScreenConnect. Disable this rule if ScreenConnect is heavily used.
level: medium

```
