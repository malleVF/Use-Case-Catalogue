---
title: "Live Memory Dump Using Powershell"
status: "test"
created: "2021/09/21"
last_modified: "2022/12/25"
tags: [t1003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Live Memory Dump Using Powershell

### Description

Detects usage of a PowerShell command to dump the live memory of a Windows machine

```yml
title: Live Memory Dump Using Powershell
id: cd185561-4760-45d6-a63e-a51325112cae
status: test
description: Detects usage of a PowerShell command to dump the live memory of a Windows machine
references:
    - https://docs.microsoft.com/en-us/powershell/module/storage/get-storagediagnosticinfo
author: Max Altgelt (Nextron Systems)
date: 2021/09/21
modified: 2022/12/25
tags:
    - attack.t1003
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains|all:
            - 'Get-StorageDiagnosticInfo'
            - '-IncludeLiveDump'
    condition: selection
falsepositives:
    - Diagnostics
level: high

```