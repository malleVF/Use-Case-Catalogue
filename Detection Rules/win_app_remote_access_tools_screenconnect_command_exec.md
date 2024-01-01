---
title: "Remote Access Tool - ScreenConnect Command Execution"
status: "experimental"
created: "2023/10/10"
last_modified: ""
tags: [execution, t1059_003, detection_rule]
logsrc_product: "windows"
logsrc_service: "application"
level: "low"
---

## Remote Access Tool - ScreenConnect Command Execution

### Description

Detects command execution via ScreenConnect RMM

```yml
title: Remote Access Tool - ScreenConnect Command Execution
id: 076ebe48-cc05-4d8f-9d41-89245cd93a14
related:
    - id: b1f73849-6329-4069-bc8f-78a604bb8b23
      type: similar
status: experimental
description: Detects command execution via ScreenConnect RMM
references:
    - https://www.huntandhackett.com/blog/revil-the-usage-of-legitimate-remote-admin-tooling
    - https://github.com/SigmaHQ/sigma/pull/4467
author: Ali Alwashali
date: 2023/10/10
tags:
    - attack.execution
    - attack.t1059.003
logsource:
    service: application
    product: windows
detection:
    selection:
        Provider_Name: 'ScreenConnect'
        EventID: 200
        Data|contains: 'Executed command of length'
    condition: selection
falsepositives:
    - Legitimate use of ScreenConnect
level: low

```