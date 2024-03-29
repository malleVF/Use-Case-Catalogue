---
title: "Cscript/Wscript Suspicious Child Process"
status: "experimental"
created: "2023/05/15"
last_modified: ""
tags: [execution, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Cscript/Wscript Suspicious Child Process

### Description

Detects suspicious child processes of Wscript/Cscript

```yml
title: Cscript/Wscript Suspicious Child Process
id: b6676963-0353-4f88-90f5-36c20d443c6a
status: experimental
description: Detects suspicious child processes of Wscript/Cscript
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/05/15
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\wscript.exe'
            - '\cscript.exe'
    selection_cli_script_main:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
    # Note: Add other combinations that are suspicious
    selection_cli_script_option_mshta:
        CommandLine|contains|all:
            - 'mshta'
            - 'http'
    selection_cli_script_option_other:
        CommandLine|contains:
            - 'rundll32'
            - 'regsvr32'
            - 'msiexec'
    condition: selection_parent and (selection_cli_script_main and 1 of selection_cli_script_option_*)
falsepositives:
    - Some false positives might occur with admin or third party software scripts. Investigate and apply additional filters accordingly.
level: medium

```
