---
title: "Delete Volume Shadow Copies Via WMI With PowerShell"
status: "stable"
created: "2021/06/03"
last_modified: "2023/10/27"
tags: [impact, t1490, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Delete Volume Shadow Copies Via WMI With PowerShell

### Description

Shadow Copies deletion using operating systems utilities via PowerShell

```yml
title: Delete Volume Shadow Copies Via WMI With PowerShell
id: 87df9ee1-5416-453a-8a08-e8d4a51e9ce1
status: stable
description: Shadow Copies deletion using operating systems utilities via PowerShell
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1490/T1490.md
    - https://www.fortinet.com/blog/threat-research/stomping-shadow-copies-a-second-look-into-deletion-methods
author: frack113
date: 2021/06/03
modified: 2023/10/27
tags:
    - attack.impact
    - attack.t1490
logsource:
    product: windows
    category: ps_classic_start
detection:
    selection:
        Data|contains|all:
            - 'Get-WmiObject'
            - 'Win32_Shadowcopy'
        Data|contains:
            - 'Delete()'
            - 'Remove-WmiObject'
    condition: selection
falsepositives:
    - Legitimate Administrator deletes Shadow Copies using operating systems utilities for legitimate reason
level: high

```