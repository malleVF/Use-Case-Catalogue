---
title: "PowerShell WMI Win32_Product Install MSI"
status: "test"
created: "2022/04/24"
last_modified: ""
tags: [defense_evasion, t1218_007, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## PowerShell WMI Win32_Product Install MSI

### Description

Detects the execution of an MSI file using PowerShell and the WMI Win32_Product class

```yml
title: PowerShell WMI Win32_Product Install MSI
id: 91109523-17f0-4248-a800-f81d9e7c081d
status: test
description: Detects the execution of an MSI file using PowerShell and the WMI Win32_Product class
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218.007/T1218.007.md
author: frack113
date: 2022/04/24
tags:
    - attack.defense_evasion
    - attack.t1218.007
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains|all:
            - 'Invoke-CimMethod '
            - '-ClassName '
            - 'Win32_Product '
            - '-MethodName '
            - '.msi'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
