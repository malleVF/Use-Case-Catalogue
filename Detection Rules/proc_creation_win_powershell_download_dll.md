---
title: "Potential DLL File Download Via PowerShell Invoke-WebRequest"
status: "experimental"
created: "2023/03/13"
last_modified: ""
tags: [command_and_control, execution, t1059_001, t1105, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Potential DLL File Download Via PowerShell Invoke-WebRequest

### Description

Detects potential DLL files being downloaded using the PowerShell Invoke-WebRequest cmdlet

```yml
title: Potential DLL File Download Via PowerShell Invoke-WebRequest
id: 0f0450f3-8b47-441e-a31b-15a91dc243e2
status: experimental
description: Detects potential DLL files being downloaded using the PowerShell Invoke-WebRequest cmdlet
references:
    - https://www.zscaler.com/blogs/security-research/onenote-growing-threat-malware-distribution
author: Florian Roth (Nextron Systems), Hieu Tran
date: 2023/03/13
tags:
    - attack.command_and_control
    - attack.execution
    - attack.t1059.001
    - attack.t1105
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'Invoke-WebRequest '
            - 'IWR '
        CommandLine|contains|all:
            - 'http'
            - 'OutFile'
            - '.dll'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
