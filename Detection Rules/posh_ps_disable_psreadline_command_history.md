---
title: "Disable Powershell Command History"
status: "test"
created: "2022/08/21"
last_modified: ""
tags: [defense_evasion, t1070_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Disable Powershell Command History

### Description

Detects scripts or commands that disabled the Powershell command history by removing psreadline module

```yml
title: Disable Powershell Command History
id: 602f5669-6927-4688-84db-0d4b7afb2150
status: test
description: Detects scripts or commands that disabled the Powershell command history by removing psreadline module
references:
    - https://twitter.com/DissectMalware/status/1062879286749773824
author: Ali Alwashali
date: 2022/08/21
tags:
    - attack.defense_evasion
    - attack.t1070.003
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains|all:
            - Remove-Module
            - psreadline
    condition: selection
falsepositives:
    - Legitimate script that disables the command history
level: high

```
