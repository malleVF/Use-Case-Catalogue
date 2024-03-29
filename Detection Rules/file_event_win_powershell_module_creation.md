---
title: "PowerShell Module File Created"
status: "experimental"
created: "2023/05/09"
last_modified: ""
tags: [persistence, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "low"
---

## PowerShell Module File Created

### Description

Detects the creation of a new PowerShell module ".psm1", ".psd1", ".dll", ".ps1", etc.

```yml
title: PowerShell Module File Created
id: e36941d0-c0f0-443f-bc6f-cb2952eb69ea
status: experimental
description: Detects the creation of a new PowerShell module ".psm1", ".psd1", ".dll", ".ps1", etc.
references:
    - Internal Research
    - https://learn.microsoft.com/en-us/powershell/scripting/developer/module/understanding-a-windows-powershell-module?view=powershell-7.3
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/05/09
tags:
    - attack.persistence
logsource:
    category: file_event
    product: windows
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        TargetFilename|contains:
            - '\WindowsPowerShell\Modules\'
            - '\PowerShell\7\Modules\'
    condition: selection
falsepositives:
    - Likely
level: low

```
