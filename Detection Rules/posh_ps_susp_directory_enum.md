---
title: "Powershell Directory Enumeration"
status: "test"
created: "2022/03/17"
last_modified: ""
tags: [discovery, t1083, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Powershell Directory Enumeration

### Description

Detects technique used by MAZE ransomware to enumerate directories using Powershell

```yml
title: Powershell Directory Enumeration
id: 162e69a7-7981-4344-84a9-0f1c9a217a52
status: test
description: Detects technique used by MAZE ransomware to enumerate directories using Powershell
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1083/T1083.md
    - https://www.mandiant.com/resources/tactics-techniques-procedures-associated-with-maze-ransomware-incidents
author: frack113
date: 2022/03/17
tags:
    - attack.discovery
    - attack.t1083
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains|all:
            - foreach
            - Get-ChildItem
            - '-Path '
            - '-ErrorAction '
            - SilentlyContinue
            - 'Out-File '
            - '-append'
    condition: selection
falsepositives:
    - Legitimate PowerShell scripts
level: medium

```