---
title: "UAC Bypass Using IDiagnostic Profile - File"
status: "test"
created: "2022/07/03"
last_modified: ""
tags: [execution, defense_evasion, privilege_escalation, t1548_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## UAC Bypass Using IDiagnostic Profile - File

### Description

Detects the creation of a file by "dllhost.exe" in System32 directory part of "IDiagnosticProfileUAC" UAC bypass technique

```yml
title: UAC Bypass Using IDiagnostic Profile - File
id: 48ea844d-19b1-4642-944e-fe39c2cc1fec
status: test
description: Detects the creation of a file by "dllhost.exe" in System32 directory part of "IDiagnosticProfileUAC" UAC bypass technique
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
    product: windows
    category: file_event
detection:
    selection:
        Image|endswith: '\DllHost.exe'
        TargetFilename|startswith: 'C:\Windows\System32\'
        TargetFilename|endswith: '.dll'
    condition: selection
falsepositives:
    - Unknown
level: high

```
