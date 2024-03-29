---
title: "Remote Thread Creation Via PowerShell In Potentially Suspicious Target"
status: "experimental"
created: "2018/06/25"
last_modified: "2023/11/10"
tags: [defense_evasion, execution, t1218_011, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Remote Thread Creation Via PowerShell In Potentially Suspicious Target

### Description

Detects the creation of a remote thread from a Powershell process in a potentially suspicious target process

```yml
title: Remote Thread Creation Via PowerShell In Potentially Suspicious Target
id: 99b97608-3e21-4bfe-8217-2a127c396a0e
related:
    - id: eeb2e3dc-c1f4-40dd-9bd5-149ee465ad50
      type: similar
status: experimental
description: Detects the creation of a remote thread from a Powershell process in a potentially suspicious target process
references:
    - https://www.fireeye.com/blog/threat-research/2018/06/bring-your-own-land-novel-red-teaming-technique.html
author: Florian Roth (Nextron Systems)
date: 2018/06/25
modified: 2023/11/10
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1218.011
    - attack.t1059.001
logsource:
    product: windows
    category: create_remote_thread
detection:
    selection:
        SourceImage|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        TargetImage|endswith:
            # Note: Please add additonal potential interesting targets to increase coverage
            - '\rundll32.exe'
            - '\regsvr32.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
