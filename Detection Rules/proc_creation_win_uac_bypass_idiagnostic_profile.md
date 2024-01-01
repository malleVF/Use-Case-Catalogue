---
title: "UAC Bypass Using IDiagnostic Profile"
status: "test"
created: "2022/07/03"
last_modified: ""
tags: [execution, defense_evasion, privilege_escalation, t1548_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## UAC Bypass Using IDiagnostic Profile

### Description

Detects the "IDiagnosticProfileUAC" UAC bypass technique

```yml
title: UAC Bypass Using IDiagnostic Profile
id: 4cbef972-f347-4170-b62a-8253f6168e6d
status: test
description: Detects the "IDiagnosticProfileUAC" UAC bypass technique
references:
    - https://github.com/Wh04m1001/IDiagnosticProfileUAC
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/07/03
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1548.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\DllHost.exe'
        ParentCommandLine|contains: ' /Processid:{12C21EA7-2EB8-4B55-9249-AC243DA8C666}'
        IntegrityLevel:
            - 'High'
            - 'System'
    condition: selection
falsepositives:
    - Unknown
level: high

```
