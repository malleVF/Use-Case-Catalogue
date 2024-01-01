---
title: "PowerShell Get-Process LSASS in ScriptBlock"
status: "test"
created: "2021/04/23"
last_modified: "2022/12/25"
tags: [credential_access, t1003_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## PowerShell Get-Process LSASS in ScriptBlock

### Description

Detects a Get-Process command on lsass process, which is in almost all cases a sign of malicious activity

```yml
title: PowerShell Get-Process LSASS in ScriptBlock
id: 84c174ab-d3ef-481f-9c86-a50d0b8e3edb
status: test
description: Detects a Get-Process command on lsass process, which is in almost all cases a sign of malicious activity
references:
    - https://twitter.com/PythonResponder/status/1385064506049630211
author: Florian Roth (Nextron Systems)
date: 2021/04/23
modified: 2022/12/25
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains: 'Get-Process lsass'
    condition: selection
falsepositives:
    - Legitimate certificate exports invoked by administrators or users (depends on processes in the environment - filter if unusable)
level: high

```