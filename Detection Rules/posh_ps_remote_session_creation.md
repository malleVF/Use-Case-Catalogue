---
title: "PowerShell Remote Session Creation"
status: "test"
created: "2022/01/06"
last_modified: "2023/01/02"
tags: [execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## PowerShell Remote Session Creation

### Description

Adversaries may abuse PowerShell commands and scripts for execution.
PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system


```yml
title: PowerShell Remote Session Creation
id: a0edd39f-a0c6-4c17-8141-261f958e8d8f
status: test
description: |
    Adversaries may abuse PowerShell commands and scripts for execution.
    PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1059.001/T1059.001.md#atomic-test-10---powershell-invoke-downloadcradle
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/new-pssession?view=powershell-7.2
author: frack113
date: 2022/01/06
modified: 2023/01/02
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains|all:
            - 'New-PSSession'
            - '-ComputerName '
    condition: selection
falsepositives:
    - Legitimate administrative script
level: medium

```