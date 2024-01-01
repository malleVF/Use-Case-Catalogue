---
title: "VsCode Powershell Profile Modification"
status: "test"
created: "2022/08/24"
last_modified: "2023/01/06"
tags: [persistence, privilege_escalation, t1546_013, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## VsCode Powershell Profile Modification

### Description

Detects the creation or modification of a vscode related powershell profile which could indicate suspicious activity as the profile can be used as a mean of persistence

```yml
title: VsCode Powershell Profile Modification
id: 3a9fa2ec-30bc-4ebd-b49e-7c9cff225502
related:
    - id: b5b78988-486d-4a80-b991-930eff3ff8bf
      type: similar
status: test
description: Detects the creation or modification of a vscode related powershell profile which could indicate suspicious activity as the profile can be used as a mean of persistence
references:
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles?view=powershell-7.2
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/08/24
modified: 2023/01/06
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1546.013
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith: '\Microsoft.VSCode_profile.ps1'
    condition: selection
falsepositives:
    - Legitimate use of the profile by developers or administrators
level: medium

```
