---
title: "Remote Access Tool - ScreenConnect Temporary File"
status: "experimental"
created: "2023/10/10"
last_modified: ""
tags: [execution, t1059_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "low"
---

## Remote Access Tool - ScreenConnect Temporary File

### Description

Detects the creation of files in a specific location by ScreenConnect RMM.
ScreenConnect has feature to remotely execute binaries on a target machine. These binaries will be dropped to ":\Users\<username>\Documents\ConnectWiseControl\Temp\" before execution.


```yml
title: Remote Access Tool - ScreenConnect Temporary File
id: 0afecb6e-6223-4a82-99fb-bf5b981e92a5
related:
    - id: b1f73849-6329-4069-bc8f-78a604bb8b23
      type: similar
status: experimental
description: |
    Detects the creation of files in a specific location by ScreenConnect RMM.
    ScreenConnect has feature to remotely execute binaries on a target machine. These binaries will be dropped to ":\Users\<username>\Documents\ConnectWiseControl\Temp\" before execution.
references:
    - https://github.com/SigmaHQ/sigma/pull/4467
author: Ali Alwashali
date: 2023/10/10
tags:
    - attack.execution
    - attack.t1059.003
logsource:
    category: file_event
    product: windows
detection:
    selection:
        Image|endswith: '\ScreenConnect.WindowsClient.exe'
        TargetFilename|contains: '\Documents\ConnectWiseControl\Temp\'
    condition: selection
falsepositives:
    - Legitimate use of ScreenConnect
level: low # Incrase the level if screenconnect is not used

```
