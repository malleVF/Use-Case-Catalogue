---
title: "Potential Suspicious PowerShell Module File Created"
status: "experimental"
created: "2023/05/09"
last_modified: ""
tags: [persistence, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Potential Suspicious PowerShell Module File Created

### Description

Detects the creation of a new PowerShell module in the first folder of the module directory structure "\WindowsPowerShell\Modules\malware\malware.psm1". This is somewhat an uncommon practice as legitimate modules often includes a version folder.

```yml
title: Potential Suspicious PowerShell Module File Created
id: e8a52bbd-bced-459f-bd93-64db45ce7657
status: experimental
description: Detects the creation of a new PowerShell module in the first folder of the module directory structure "\WindowsPowerShell\Modules\malware\malware.psm1". This is somewhat an uncommon practice as legitimate modules often includes a version folder.
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
        TargetFilename|endswith:
            # Note: Don't include PowerShell 7 as it has default modules that don't follow this logic
            - '\\WindowsPowerShell\\Modules\\*\.ps'
            - '\\WindowsPowerShell\\Modules\\*\.dll'
    condition: selection
falsepositives:
    - False positive rate will vary depending on the environments. Additional filters might be required to make this logic usable in production.
level: medium

```
